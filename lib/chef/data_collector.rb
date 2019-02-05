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
require "chef/data_collector/helpers"
require "chef/data_collector/node_uuid"
require "chef/data_collector/run_end_message"

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
      include Chef::DataCollector::Helpers

      attr_reader :status
      attr_reader :exception
      attr_reader :expanded_run_list
      attr_reader :run_status
      attr_reader :deprecations
      attr_reader :action_collection

      # handle to the events object so we can deregister
      # @api private
      attr_reader :events

      def initialize(events)
        @events = events
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

        # publish our node_uuid back to the node data object
        run_status.run_context.node.automatic[:chef_guid] = Chef::DataCollector::NodeUUID.node_uuid(run_status.run_context.node)

        # do sanity checks
        validate_data_collector_server_url!
        validate_data_collector_output_locations! if Chef::Config[:data_collector][:output_locations]

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
        send_run_completion("success")
      end

      # see EventDispatch::Base#run_failed
      def run_failed(exception)
        send_run_completion("failure")
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

      # see EventDispatch::Base#deprecation
      # Append a received deprecation to the list of deprecations
      def deprecation(message, location = caller(2..2)[0])
        add_deprecation(message.message, message.url, location)
      end

      private

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
      def send_run_completion(status)
        # If run_status is nil we probably failed before the client triggered
        # the run_started callback. In this case we'll skip updating because
        # we have nothing to report.
        return unless run_status

        message = Chef::DataCollector::RunEndMessage.construct_message(self, status)
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

      def add_deprecation(message, url, location)
        @deprecations << { message: message, url: url, location: location }
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
          "entity_uuid" => Chef::DataCollector::NodeUUID.node_uuid(run_status.run_context.node),
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
