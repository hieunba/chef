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

class Chef
  class DataCollector
    module MessageHelpers
      private

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
    end
  end
end
