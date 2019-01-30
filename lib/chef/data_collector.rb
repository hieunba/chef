#
# Author:: Adam Leff (<adamleff@chef.io>)
# Author:: Ryan Cragun (<ryan@chef.io>)
#
# Copyright:: Copyright 2012-2019, Chef Software Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require "uri"
require "chef/server_api"
require "chef/http/simple_json"
require "chef/event_dispatch/base"
require "ostruct"
require "set"

class Chef

  # == Chef::DataCollector
  # Provides methods for determinine whether a reporter should be registered.
  class DataCollector
    # == Chef::DataCollector::Reporter
    # Provides an event handler that can be registered to report on Chef
    # run data. Unlike the existing Chef::ResourceReporter event handler,
    # the DataCollector handler is not tied to a Chef Server / Chef Reporting
    # and exports its data through a webhook-like mechanism to a configured
    # endpoint.
    class Reporter < EventDispatch::Base

      attr_reader :status
      attr_reader :exception
      attr_reader :error_descriptions
      attr_reader :expanded_run_list
      attr_reader :run_status
      attr_reader :current_resource_report
      attr_reader :deprecations
      attr_reader :action_collection

      # handle to the events object so we can deregister
      # @api private
      attr_reader :events

      def initialize(events)
        @events = events
        @current_resource_loaded = nil
        @error_descriptions      = {}
        @expanded_run_list       = {}
        @deprecations            = Set.new
      end

      # see EventDispatch::Base#run_started
      # Upon receipt, we will send our run start message to the
      # configured DataCollector endpoint. Depending on whether
      # the user has configured raise_on_failure, if we cannot
      # send the message, we will either disable the DataCollector
      # Reporter for the duration of this run, or we'll raise an
      # exception.
      def run_started(current_run_status)
        @run_status = current_run_status

        # do sanity checks
        validate_data_collector_server_url!
        validate_data_collector_output_locations! if Chef::Config[:data_collector][:output_locations]

        generate_guid

        message = run_start_message(run_status)
        disable_reporter_on_error do
          send_to_data_collector(message)
        end
        send_to_output_locations(message) if Chef::Config[:data_collector][:output_locations]
      end

      # see EventDispatch::Base#run_completed
      # Upon receipt, we will send our run completion message to the
      # configured DataCollector endpoint.
      def run_completed(node)
        send_run_completion(status: "success")
      end

      # see EventDispatch::Base#run_failed
      def run_failed(exception)
        send_run_completion(status: "failure")
      end

      def action_collection_registration(action_collection)
        @action_collection = action_collection
        action_collection.register(self) if should_be_enabled?
      end

      # see EventDispatch::Base#run_list_expanded
      # The expanded run list is stored for later use by the run_completed
      # event and message.
      def run_list_expanded(run_list_expansion)
        @expanded_run_list = run_list_expansion
      end

      # see EventDispatch::Base#run_list_expand_failed
      # The run error text is updated with the output of the appropriate
      # formatter.
      def run_list_expand_failed(node, exception)
        update_error_description(
          Formatters::ErrorMapper.run_list_expand_failed(
            node,
            exception
          ).for_json
        )
      end

      # see EventDispatch::Base#cookbook_resolution_failed
      # The run error text is updated with the output of the appropriate
      # formatter.
      def cookbook_resolution_failed(expanded_run_list, exception)
        update_error_description(
          Formatters::ErrorMapper.cookbook_resolution_failed(
            expanded_run_list,
            exception
          ).for_json
        )
      end

      # see EventDispatch::Base#cookbook_sync_failed
      # The run error text is updated with the output of the appropriate
      # formatter.
      def cookbook_sync_failed(cookbooks, exception)
        update_error_description(
          Formatters::ErrorMapper.cookbook_sync_failed(
            cookbooks,
            exception
          ).for_json
        )
      end

      # see EventDispatch::Base#deprecation
      # Append a received deprecation to the list of deprecations
      def deprecation(message, location = caller(2..2)[0])
        add_deprecation(message.message, message.url, location)
      end

      private

      # get only the top level resources and strip out the subcollections
      def action_records
        @action_records ||= action_collection.filtered_collection(max_nesting: 0)
      end

      # strip out everything other than top-level updated resources and count them
      def updated_resource_count
        action_collection.filtered_collection(max_nesting: 0, up_to_date: false, skipped: false, unprocessed: false, failed: false).size
      end

      # Selects the type of HTTP client to use based on whether we are using
      # token-based or signed header authentication. Token authentication is
      # intended to be used primarily for Chef Solo in which case no signing
      # key will be available (in which case `Chef::ServerAPI.new()` would
      # raise an exception.
      # FIXME: rename to "http_client"
      def http
        @http ||= setup_http_client(Chef::Config[:data_collector][:server_url])
      end

      # FIXME: rename to "http_clients_for_output_locations" or something
      def http_output_locations
        @http_output_locations ||=
          begin
            if Chef::Config[:data_collector][:output_locations]
              Chef::Config[:data_collector][:output_locations][:urls].each_with_object({}) do |location_url, http_output_locations|
                http_output_locations[location_url] = setup_http_client(location_url)
              end
            end
          end
      end

      def setup_http_client(url)
        if Chef::Config[:data_collector][:token].nil?
          Chef::ServerAPI.new(url, validate_utf8: false)
        else
          Chef::HTTP::SimpleJSON.new(url, validate_utf8: false)
        end
      end

      #
      # Yields to the passed-in block (which is expected to be some interaction
      # with the DataCollector endpoint). If some communication failure occurs,
      # either disable any future communications to the DataCollector endpoint, or
      # raise an exception (if the user has set
      # Chef::Config.data_collector.raise_on_failure to true.)
      #
      # @param block [Proc] A ruby block to run. Ignored if a command is given.
      #
      def disable_reporter_on_error
        yield
      rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET,
        Errno::ECONNREFUSED, EOFError, Net::HTTPBadResponse,
        Net::HTTPHeaderSyntaxError, Net::ProtocolError, OpenSSL::SSL::SSLError,
        Errno::EHOSTDOWN => e
        # Do not disable data collector reporter if additional output_locations have been specified
        events.deregister(self) unless Chef::Config[:data_collector][:output_locations]

        code = if e.respond_to?(:response) && e.response.code
                 e.response.code.to_s
               else
                 "Exception Code Empty"
               end

        msg = "Error while reporting run start to Data Collector. " \
          "URL: #{Chef::Config[:data_collector][:server_url]} " \
          "Exception: #{code} -- #{e.message} "

        if Chef::Config[:data_collector][:raise_on_failure]
          Chef::Log.error(msg)
          raise
        else
          # Make the message non-scary for folks who don't have automate:
          msg << " (This is normal if you do not have Chef Automate)"
          Chef::Log.info(msg)
        end
      end

      def send_to_data_collector(message)
        http.post(nil, message, headers) if Chef::Config[:data_collector][:server_url]
      end

      def send_to_output_locations(message)
        Chef::Config[:data_collector][:output_locations].each do |type, location_list|
          location_list.each do |l|
            handle_output_location(type, l, message)
          end
        end
      end

      def handle_output_location(type, loc, message)
        type == :urls ? send_to_http_location(loc, message) : send_to_file_location(loc, message)
      end

      def send_to_file_location(file_name, message)
        open(file_name, "a") { |f| f.puts message }
      end

      def send_to_http_location(http_url, message)
        @http_output_locations[http_url].post(nil, message, headers) if @http_output_locations[http_url]
      rescue
        Chef::Log.trace("Data collector failed to send to URL location #{http_url}. Please check your configured data_collector.output_locations")
      end

      #
      # Send any messages to the DataCollector endpoint that are necessary to
      # indicate the run has completed. Currently, two messages are sent:
      #
      # - An "action" message with the node object indicating it's been updated
      # - An "run_converge" (i.e. RunEnd) message with details about the run,
      #   what resources were modified/up-to-date/skipped, etc.
      #
      # @param opts [Hash] Additional details about the run, such as its success/failure.
      #
      def send_run_completion(opts)
        # If run_status is nil we probably failed before the client triggered
        # the run_started callback. In this case we'll skip updating because
        # we have nothing to report.
        return unless run_status

        message = run_end_message( # FIXME: remove all arguments
          run_status: run_status,
          expanded_run_list: expanded_run_list,
          resources: all_resource_reports,
          status: opts[:status],
          error_descriptions: error_descriptions,
          deprecations: deprecations.to_a
        )
        disable_reporter_on_error do
          send_to_data_collector(message)
        end
        send_to_output_locations(message) if Chef::Config[:data_collector][:output_locations]
      end

      def headers
        headers = { "Content-Type" => "application/json" }

        unless Chef::Config[:data_collector][:token].nil?
          headers["x-data-collector-token"] = Chef::Config[:data_collector][:token]
          headers["x-data-collector-auth"]  = "version=1.0"
        end

        headers
      end

      # If the identity property has been lazied (via a lazy name resource) evaluating it
      # for an unprocessed resource (where the preconditions have not been met) may cause the lazy
      # evaluator to throw -- and would otherwise crash the data collector.
      #
      def safe_resource_identity(new_resource)
        new_resource.identity.to_s
      rescue => e
        "unknown identity (due to #{e.class})"
      end

      def safe_state_for_resource_reporter(resource)
        resource ? resource.state_for_resource_reporter : {}
      rescue
        {}
      end

      def action_record_status_for_json(action_record)
        action = action_record.status.to_s
        action = "up-to-date" if action == "up_to_date"
        action
      end

      def updated_or_failed?(action_record)
        action_record.status == :updated || action_record.status == :failed
      end

      def action_record_for_json(action_record)
        new_resource = action_record.new_resource
        current_resource = action_record.current_resource

        hash = {
          "type" => new_resource.resource_name.to_sym,
          "name" => new_resource.name.to_s,
          "id" => safe_resource_identity(new_resource),
          "after" => safe_state_for_resource_reporter(new_resource),
          "before" => safe_state_for_resource_reporter(current_resource),
          "duration" => action_record.elapsed_time.nil? ? "" : (action_record.elapsed_time * 1000).to_i.to_s,
          "delta" => new_resource.respond_to?(:diff) && updated_or_failed?(action_record) ? new_resource.diff : "",
          "ignore_failure" => new_resource.ignore_failure,
          "result" => action_record.action.to_s,
          "status" => action_record_status_for_json(action_record),
        }

        if new_resource.cookbook_name
          hash["cookbook_name"]    = new_resource.cookbook_name
          hash["cookbook_version"] = new_resource.cookbook_version.version
          hash["recipe_name"]      = new_resource.recipe_name
        end

        hash["conditional"] = action_record.conditional.to_text if action_record.status == :skipped
        hash["error_message"] = action_record.exception.message unless action_record.exception.nil?

        hash
      end

      def all_resource_reports
        action_records.map { |rec| action_record_for_json(rec) }
      end

      def update_error_description(discription_hash)
        @error_descriptions = discription_hash
      end

      def add_deprecation(message, url, location)
        @deprecations << { message: message, url: url, location: location }
      end

      def initialize_resource_report_if_needed(new_resource, action, current_resource = nil)
        return unless current_resource_report.nil?
        @current_resource_report = create_resource_report(new_resource, action, current_resource)
      end

      def create_resource_report(new_resource, action, current_resource = nil)
        Chef::DataCollector::ResourceReport.new(
          new_resource,
          action,
          current_resource
        )
      end

      def clear_current_resource_report
        @current_resource_report = nil
      end

      def validate_and_return_uri(uri)
        URI(uri)
      rescue URI::InvalidURIError
        nil
      end

      def validate_and_create_file(file)
        send_to_file_location(file, "")
        true
        # Rescue exceptions raised by the file path being non-existent or not writeable and re-raise them to the user
        # with clearer explanatory text.
      rescue Errno::ENOENT
        raise Chef::Exceptions::ConfigurationError,
          "Chef::Config[:data_collector][:output_locations][:files] contains the location #{file}, which is a non existent file path."
      rescue Errno::EACCES
        raise Chef::Exceptions::ConfigurationError,
          "Chef::Config[:data_collector][:output_locations][:files] contains the location #{file}, which cannnot be written to by Chef."
      end

      def validate_data_collector_server_url!
        unless !Chef::Config[:data_collector][:server_url] && Chef::Config[:data_collector][:output_locations]
          uri = validate_and_return_uri(Chef::Config[:data_collector][:server_url])
          unless uri
            raise Chef::Exceptions::ConfigurationError, "Chef::Config[:data_collector][:server_url] (#{Chef::Config[:data_collector][:server_url]}) is not a valid URI."
          end

          if uri.host.nil?
            raise Chef::Exceptions::ConfigurationError,
              "Chef::Config[:data_collector][:server_url] (#{Chef::Config[:data_collector][:server_url]}) is a URI with no host. Please supply a valid URL."
          end
        end
      end

      def handle_type(type, loc)
        type == :urls ? validate_and_return_uri(loc) : validate_and_create_file(loc)
      end

      def validate_data_collector_output_locations!
        if Chef::Config[:data_collector][:output_locations].empty?
          raise Chef::Exceptions::ConfigurationError,
            "Chef::Config[:data_collector][:output_locations] is empty. Please supply an hash of valid URLs and / or local file paths."
        end

        Chef::Config[:data_collector][:output_locations].each do |type, locations|
          locations.each do |l|
            unless handle_type(type, l)
              raise Chef::Exceptions::ConfigurationError,
                "Chef::Config[:data_collector][:output_locations] contains the location #{l} which is not valid."
            end
          end
        end
      end

      #
      # Message payload that is sent to the DataCollector server at the
      # start of a Chef run.
      #
      # @param run_status [Chef::RunStatus] The RunStatus instance for this node/run.
      #
      # @return [Hash] A hash containing the run start message data.
      #
      def run_start_message(run_status)
        {
          "chef_server_fqdn" => chef_server_fqdn,
          "entity_uuid" => node_uuid,
          "id" => run_status.run_id,
          "message_version" => "1.0.0",
          "message_type" => "run_start",
          "node_name" => run_status.node.name,
          "organization_name" => organization,
          "run_id" => run_status.run_id,
          "source" => collector_source,
          "start_time" => run_status.start_time.utc.iso8601,
        }
      end

      #
      # Message payload that is sent to the DataCollector server at the
      # end of a Chef run.
      #
      # @param reporter_data [Hash] Data supplied by the Reporter, such as run_status, resource counts, etc.
      #
      # @return [Hash] A hash containing the run end message data.
      #
      def run_end_message(reporter_data)
        run_status = reporter_data[:run_status]

        message = {
          "chef_server_fqdn" => chef_server_fqdn,
          "entity_uuid" => node_uuid,
          "expanded_run_list" => reporter_data[:expanded_run_list],
          "id" => run_status.run_id,
          "message_version" => "1.1.0",
          "message_type" => "run_converge",
          "node" => run_status.node,
          "node_name" => run_status.node.name,
          "organization_name" => organization,
          "resources" => reporter_data[:resources],
          "run_id" => run_status.run_id,
          "run_list" => run_status.node.run_list.for_json,
          "policy_name" => run_status.node.policy_name,
          "policy_group" => run_status.node.policy_group,
          "start_time" => run_status.start_time.utc.iso8601,
          "end_time" => run_status.end_time.utc.iso8601,
          "source" => collector_source,
          "status" => reporter_data[:status],
          "total_resource_count" => reporter_data[:resources].count,
          "updated_resource_count" => updated_resource_count,
          "deprecations" => reporter_data[:deprecations],
        }

        if run_status.exception
          message["error"] = {
            "class" => run_status.exception.class,
            "message" => run_status.exception.message,
            "backtrace" => run_status.exception.backtrace,
            "description" => action_collection.error_descriptions,
          }
        end

        message
      end

      #
      # Fully-qualified domain name of the Chef Server configured in Chef::Config
      # If the chef_server_url cannot be parsed as a URI, the node["fqdn"] attribute
      # will be returned, or "localhost" if the run_status is unavailable to us.
      #
      # @return [String] FQDN of the configured Chef Server, or node/localhost if not found.
      #
      def chef_server_fqdn
        if !Chef::Config[:chef_server_url].nil?
          URI(Chef::Config[:chef_server_url]).host
        elsif !Chef::Config[:node_name].nil?
          Chef::Config[:node_name]
        else
          "localhost"
        end
      end

      #
      # The organization name the node is associated with. For Chef Solo runs, a
      # user-configured organization string is returned, or the string "chef_solo"
      # if such a string is not configured.
      #
      # @return [String] Organization to which the node is associated
      #
      def organization
        solo_run? ? data_collector_organization : chef_server_organization
      end

      #
      # Returns the user-configured organization, or "chef_solo" if none is configured.
      #
      # This is only used when Chef is run in Solo mode.
      #
      # @return [String] Data-collector-specific organization used when running in Chef Solo
      #
      def data_collector_organization
        Chef::Config[:data_collector][:organization] || "chef_solo"
      end

      #
      # Return the organization assumed by the configured chef_server_url.
      #
      # We must parse this from the Chef::Config[:chef_server_url] because a node
      # has no knowledge of an organization or to which organization is belongs.
      #
      # If we cannot determine the organization, we return "unknown_organization"
      #
      # @return [String] shortname of the Chef Server organization
      #
      def chef_server_organization
        return "unknown_organization" unless Chef::Config[:chef_server_url]

        Chef::Config[:chef_server_url].match(%r{/+organizations/+([a-z0-9][a-z0-9_-]{0,254})}).nil? ? "unknown_organization" : $1
      end

      #
      # The source of the data collecting during this run, used by the
      # DataCollector endpoint to determine if Chef was in Solo mode or not.
      #
      # @return [String] "chef_solo" if in Solo mode, "chef_client" if in Client mode
      #
      def collector_source
        solo_run? ? "chef_solo" : "chef_client"
      end

      #
      # If we're running in Solo (legacy) mode, or in Solo (formerly
      # "Chef Client Local Mode"), we're considered to be in a "solo run".
      #
      # @return [Boolean] Whether we're in a solo run or not
      #
      def solo_run?
        Chef::Config[:solo] || Chef::Config[:local_mode]
      end

      #
      # Returns a UUID that uniquely identifies this node for reporting reasons.
      #
      # The node is read in from disk if it exists, or it's generated if it does
      # does not exist.
      #
      # @return [String] UUID for the node
      #
      def node_uuid
        Chef::Config[:chef_guid] || read_node_uuid || generate_node_uuid
      end

      #
      # Generates a UUID for the node via SecureRandom.uuid and writes out
      # metadata file so the UUID persists between runs.
      #
      # @return [String] UUID for the node
      #
      def generate_node_uuid
        uuid = SecureRandom.uuid
        update_metadata("node_uuid", uuid)

        uuid
      end

      #
      # Reads in the node UUID from the node metadata file
      #
      # @return [String] UUID for the node
      #
      def read_node_uuid
        metadata["node_uuid"]
      end

      METADATA_FILENAME = "data_collector_metadata.json".freeze

      #
      # Returns the DataCollector metadata for this node
      #
      # If the metadata file does not exist in the file cache path,
      # an empty hash will be returned.
      #
      # @return [Hash] DataCollector metadata for this node
      #
      def metadata
        Chef::JSONCompat.parse(Chef::FileCache.load(METADATA_FILENAME))
      rescue Chef::Exceptions::FileNotFound
        {}
      end

      def update_metadata(key, value)
        updated_metadata = metadata.tap { |x| x[key] = value }
        Chef::FileCache.store(METADATA_FILENAME, Chef::JSONCompat.to_json(updated_metadata), 0644)
      end

      # Ensure that we have a GUID for this node
      # If we've got the proper configuration, we'll simply set that.
      # If we're registed with the data collector, we'll migrate that UUID into our configuration and use that
      # Otherwise, we'll create a new GUID and save it
      def generate_guid
        Chef::Config[:chef_guid] ||=
          if File.exists?(Chef::Config[:chef_guid_path])
            File.read(Chef::Config[:chef_guid_path])
          else
            uuid = UUIDFetcher.node_uuid
            File.open(Chef::Config[:chef_guid_path], "w+") do |fh|
              fh.write(uuid)
            end
            uuid
          end
      end

      # Whether or not to enable data collection:
      # * always disabled for why run mode
      # * disabled when the user sets `Chef::Config[:data_collector][:mode]` to a
      #   value that excludes the mode (client or solo) that we are running as
      # * disabled in solo mode if the user did not configure the auth token
      # * disabled if `Chef::Config[:data_collector][:server_url]` is set to a
      #   falsey value
      def should_be_enabled?
        solo = Chef::Config[:solo] || Chef::Config[:local_mode]
        mode = Chef::Config[:data_collector][:mode]

        if Chef::Config[:why_run]
          Chef::Log.trace("data collector is disabled for why run mode")
          false
        end
        unless mode == :both || solo && mode == :solo || !solo && mode == :client
          Chef::Log.trace("data collector is configured to only run in " \
                          "#{Chef::Config[:data_collector][:mode].inspect} modes, disabling it")
          false
        end
        unless Chef::Config[:data_collector][:server_url] || Chef::Config[:data_collector][:output_locations]
          Chef::Log.trace("Neither data collector URL or output locations have been configured, disabling data collector")
          false
        end
        if solo && !Chef::Config[:data_collector][:token]
          Chef::Log.trace("Data collector token must be configured to use Chef Automate data collector with Chef Solo")
          false
        end
        if !solo && Chef::Config[:data_collector][:token]
          Chef::Log.warn("Data collector token authentication is not recommended for client-server mode" \
                         "Please upgrade Chef Server to 12.11.0 and remove the token from your config file " \
                         "to use key based authentication instead")
        end
        true
      end

    end
  end
end
