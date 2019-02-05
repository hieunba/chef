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
    module NodeUUID
      class << self
        #
        # Returns a UUID that uniquely identifies this node for reporting reasons.
        #
        # The node is read in from disk if it exists, or it's generated if it does
        # does not exist.
        #
        # @return [String] UUID for the node
        #
        def node_uuid(node)
          Chef::Config[:chef_guid] ||= read_node_uuid || generate_node_uuid(node)
        end

        private

        #
        # Generates a UUID for the node via SecureRandom.uuid and writes out
        # metadata file so the UUID persists between runs.
        #
        # @return [String] UUID for the node
        #
        def generate_node_uuid(node)
          uuid = node[:chef_guid] || SecureRandom.uuid
          File.open(Chef::Config[:chef_guid_path], "w+") do |fh|
            fh.write(uuid)
          end

          uuid
        end

        #
        # Reads in the node UUID from the node metadata file
        #
        # @return [String] UUID for the node
        #
        def read_node_uuid
          if File.exists?(Chef::Config[:chef_guid_path])
            File.read(Chef::Config[:chef_guid_path])
          end
        end
      end
    end
  end
end
