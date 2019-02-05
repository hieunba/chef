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

require "chef/data_collector/helpers"
require "chef/data_collector/node_uuid"

class Chef
  class DataCollector
    module RunEndMessage
      extend Chef::DataCollector::Helpers

      class << self
        #
        # Message payload that is sent to the DataCollector server at the
        # end of a Chef run.
        #
        # @param reporter_data [Hash] Data supplied by the Reporter, such as run_status, resource counts, etc.
        #
        # @return [Hash] A hash containing the run end message data.
        #
        def construct_message(data_collector, status)
          action_collection = data_collector.action_collection

          message = {
            "chef_server_fqdn" => chef_server_fqdn,
            "entity_uuid" => Chef::DataCollector::NodeUUID.node_uuid(data_collector.run_status.node),
            "expanded_run_list" => data_collector.expanded_run_list,
            "id" => data_collector.run_status.run_id,
            "message_version" => "1.1.0",
            "message_type" => "run_converge",
            "node" => data_collector.run_status.node,
            "node_name" => data_collector.run_status.node.name,
            "organization_name" => organization,
            "resources" => all_resource_reports(action_collection),
            "run_id" => data_collector.run_status.run_id,
            "run_list" => data_collector.run_status.node.run_list.for_json,
            "policy_name" => data_collector.run_status.node.policy_name,
            "policy_group" => data_collector.run_status.node.policy_group,
            "start_time" => data_collector.run_status.start_time.utc.iso8601,
            "end_time" => data_collector.run_status.end_time.utc.iso8601,
            "source" => collector_source,
            "status" => status,
            "total_resource_count" => all_resource_reports(action_collection).count,
            "updated_resource_count" => updated_resource_count(action_collection),
            "deprecations" => data_collector.deprecations,
          }

          if data_collector.run_status.exception
            message["error"] = {
              "class" => data_collector.run_status.exception.class,
              "message" => data_collector.run_status.exception.message,
              "backtrace" => data_collector.run_status.exception.backtrace,
              "description" => data_collector.action_collection.error_descriptions,
            }
          end

          message
        end

        private

        # strip out everything other than top-level updated resources and count them
        def updated_resource_count(action_collection)
          action_collection.filtered_collection(max_nesting: 0, up_to_date: false, skipped: false, unprocessed: false, failed: false).size
        end

        # get only the top level resources and strip out the subcollections
        def action_records(action_collection)
          action_collection.filtered_collection(max_nesting: 0)
        end

        def all_resource_reports(action_collection)
          action_records(action_collection).map { |rec| action_record_for_json(rec) }
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
      end
    end
  end
end
