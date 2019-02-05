#
# Copyright:: Copyright 2019-2019, Chef Software Inc.
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

require File.expand_path("../../spec_helper", __FILE__)
require "chef/data_collector"
require "socket"

describe Chef::DataCollector do
  before(:each) do
    Chef::Config[:enable_reporting] = true
  end

  let(:node) { Chef::Node.new }

  let(:rest_client) { double("Chef::ServerAPI (mock)") }

  let(:data_collector) { Chef::DataCollector::Reporter.new(events) }

  let(:new_resource) { Chef::Resource::File.new("/tmp/a-file.txt") }

  let(:current_resource) { Chef::Resource::File.new("/tmp/a-file.txt") }

  let(:events) { Chef::EventDispatch::Dispatcher.new }

  let(:run_context) { Chef::RunContext.new(node, {}, events) }

  let(:run_status) { Chef::RunStatus.new(node, events) }

  let(:start_time) { Time.new }

  let(:end_time) { Time.new + 20 }

  let(:run_list) { Chef::RunList.new }

  let(:run_id) { run_status.run_id }

  let(:expansion) { Chef::RunList::RunListExpansion.new("_default", run_list.run_list_items) }

  let(:cookbook_name) { "monkey" }

  let(:recipe_name) { "atlas" }

  let(:node_name) { "spitfire" }

  let(:cookbook_version) { double("Cookbook::Version", version: "1.2.3") }

  let(:resource_record) { [] }

  let(:exception) { nil }

  let(:action_collection) { Chef::ActionCollection.new }

  before do
    allow(Chef::HTTP::SimpleJSON).to receive(:new).and_return(rest_client)
    allow(Chef::ServerAPI).to receive(:new).and_return(rest_client)
    node.name(node_name)
    new_resource.cookbook_name = cookbook_name
    new_resource.recipe_name = recipe_name
    allow(new_resource).to receive(:cookbook_version).and_return(cookbook_version)
    run_list << "recipe[lobster]" << "role[rage]" << "recipe[fist]"
    allow(Time).to receive(:now).and_return(start_time, end_time)
    events.register(action_collection)
    events.register(data_collector)
  end

  def expect_start_message
    expect(rest_client).to receive(:post).with(
      nil,
      {
        "chef_server_fqdn" => "localhost",
        "entity_uuid" => "779196c6-f94f-4501-9dae-af8081ab4d3a", # FIXME
        "id" => nil,
        "message_type" => "run_start",
        "message_version" => "1.0.0",
        "node_name" => node_name,
        "organization_name" => "unknown_organization",
        "run_id" => run_status.run_id,
        "source" => "chef_client",
        "start_time" => run_status&.start_time&.utc&.iso8601,
      },
      { "Content-Type" => "application/json" }
    )
  end

  def expect_converge_message(keys)
    keys["message_type"] = "run_converge"
    keys["message_version"] = "1.1.0"
    expect(rest_client).to receive(:post).with(
      nil,
      hash_including(keys),
      { "Content-Type" => "application/json" }
    )
  end

  def resource_has_diff(new_resource, status)
    new_resource.respond_to?(:diff) && %w{updated failed}.include?(status)
  end

  def resource_record_for(current_resource, new_resource, action, status)
    {
      "after" => new_resource.state_for_resource_reporter,
      "before" => current_resource&.state_for_resource_reporter,
      "cookbook_name" => cookbook_name,
      "cookbook_version" => cookbook_version.version,
      "delta" => resource_has_diff(new_resource, status) ? new_resource.diff : "",
      "duration" => (new_resource.elapsed_time.nil? ? nil : ( new_resource.elapsed_time * 1000 ).to_i).to_s,
      "id" => new_resource.identity,
      "ignore_failure" => new_resource.ignore_failure,
      "name" => new_resource.name,
      "recipe_name" => recipe_name,
      "result" => action.to_s,
      "status" => status,
      "type" => new_resource.resource_name.to_sym,
    }
  end

  describe "when the start of the run fails" do
    let(:exception) { Exception.new("imperial to metric conversion error") }

    it "should report failure when the run list expansion fails" do
      # this never starts the clock or calls run_started
      raise "FIXME"
  #    expect_start_message
  #    expect_converge_message("chef_server_fqdn"=>"localhost")
      # events.run_list_expand_failed(node, exception)
      # events.run_failed(exception, run_status)
    end

  end

  describe "after successfully starting the run" do
    before do
      events.run_list_expanded(expansion)
      run_status.start_clock
      events.cookbook_compilation_start(run_context)
    end

    describe "initialization" do
      it "the default :server_url is based on the :chef_server_url" do
        # i had no idea there was a default :chef_server_url
        expect(Chef::Config[:chef_server_url]).to eql("https://localhost:443")
        expect(Chef::Config[:data_collector][:server_url]).to eql("https://localhost:443/data-collector")
      end

      it "the default :output_locations is nil" do
        expect(Chef::Config[:data_collector][:output_locations]).to be nil
      end
    end

    describe "run_start_message" do
      it "does it" do
        run_status.run_context = run_context
        expect_start_message
        events.run_started(run_status)
      end

      it "if there is no server_url or output_location it does not send a message" do
        Chef::Config[:data_collector][:server_url] = nil
        Chef::Config[:data_collector][:output_locations] = nil
        expect(rest_client).not_to receive(:post)
        events.run_started(run_status)
      end

      it "in why-run mode it does not send a message" do
        Chef::Config[:why_run] = true
        expect(rest_client).not_to receive(:post)
        events.run_started(run_status)
      end
    end

    describe "converge messages" do
      before do
        run_status.run_context = run_context
        expect_start_message
        events.run_started(run_status)
        events.converge_start(run_context)
      end

      def send_run_failed_or_completed_event
        status == "success" ? events.run_completed(node) : events.run_failed(exception, run_status)
      end

      shared_examples_for "sends a converge message" do
        it "has a chef_server_fqdn" do
          expect_converge_message("chef_server_fqdn" => "localhost") # FIXME?
          send_run_failed_or_completed_event
        end

        it "has a start_time" do
          expect_converge_message("start_time" => run_status.start_time.utc.iso8601)
          send_run_failed_or_completed_event
        end

        it "has a end_time" do
          expect_converge_message("end_time" => run_status.end_time.utc.iso8601)
          send_run_failed_or_completed_event
        end

        it "has a entity_uuid" do
          expect_converge_message("entity_uuid" => "779196c6-f94f-4501-9dae-af8081ab4d3a") # FIXME
          send_run_failed_or_completed_event
        end

        it "has a expanded_run_list" do
          expect_converge_message("expanded_run_list" => expansion)
          send_run_failed_or_completed_event
        end

        it "has a node" do
          expect_converge_message("node" => node)
          send_run_failed_or_completed_event
        end

        it "has a node_name" do
          expect_converge_message("node_name" => "spitfire")
          send_run_failed_or_completed_event
        end

        it "has an organization" do
          expect_converge_message("organization_name" => "unknown_organization") # FIXME?
          send_run_failed_or_completed_event
        end

        it "has a policy_group" do
          expect_converge_message("policy_group" => nil) # FIXME?
          send_run_failed_or_completed_event
        end

        it "has a policy_name" do
          expect_converge_message("policy_name" => nil) # FIXME?
          send_run_failed_or_completed_event
        end

        it "has a run_id" do
          expect_converge_message("run_id" => nil) # FIXME
          send_run_failed_or_completed_event
        end

        it "has a run_list" do
          expect_converge_message("run_list" => []) # FIXME
          send_run_failed_or_completed_event
        end

        it "has a source" do
          expect_converge_message("source" => "chef_client") # FIXME
          send_run_failed_or_completed_event
        end

        it "has a status" do
          expect_converge_message("status" => status)
          send_run_failed_or_completed_event
        end

        it "has no deprecations" do # FIXME
          expect_converge_message("deprecations" => [])
          send_run_failed_or_completed_event
        end

        it "has an error field" do
          if exception
            expect_converge_message(
              "error" => {
                "class" => exception.class,
                "message" => exception.message,
                "backtrace" => exception.backtrace,
                "description" => error_description,
              }
            )
          else
            expect(rest_client).to receive(:post).with(
              nil,
              hash_excluding("error"),
              { "Content-Type" => "application/json" }
            )
          end
          send_run_failed_or_completed_event
        end

        it "has a total resource count of zero" do
          expect_converge_message("total_resource_count" => total_resource_count)
          send_run_failed_or_completed_event
        end

        it "has a updated resource count of zero" do
          expect_converge_message("updated_resource_count" => updated_resource_count)
          send_run_failed_or_completed_event
        end

        it "includes the resource record" do
          expect_converge_message("resources" => resource_record)
          send_run_failed_or_completed_event
        end
      end

      context "when the run contains a file resource that is up-to-date" do
        let(:total_resource_count) { 1 }
        let(:updated_resource_count) { 0 }
        let(:resource_record) { [ resource_record_for(current_resource, new_resource, :create, "up-to-date") ] }
        let(:status) { "success" }

        before do
          events.resource_action_start(new_resource, :create)
          events.resource_current_state_loaded(new_resource, :create, current_resource)
          events.resource_up_to_date(new_resource, :create)
          events.resource_completed(new_resource)
          events.converge_complete
          run_status.stop_clock
        end

        it_behaves_like "sends a converge message"
      end

      context "when the run contains a file resource that is updated" do
        let(:total_resource_count) { 1 }
        let(:updated_resource_count) { 1 }
        let(:resource_record) { [ resource_record_for(current_resource, new_resource, :create, "updated") ] }
        let(:status) { "success" }

        before do
          events.resource_action_start(new_resource, :create)
          events.resource_current_state_loaded(new_resource, :create, current_resource)
          events.resource_updated(new_resource, :create)
          events.resource_completed(new_resource)
          events.converge_complete
          run_status.stop_clock
        end

        it_behaves_like "sends a converge message"
      end

      context "When there is an embedded resource, it omits reporting the sub-resource" do
        let(:total_resource_count) { 1 }
        let(:updated_resource_count) { 1 }
        let(:resource_record) { [ resource_record_for(current_resource, new_resource, :create, "updated") ] }
        let(:status) { "success" }

        before do
          events.resource_action_start(new_resource, :create)
          events.resource_current_state_loaded(new_resource, :create, current_resource)

          implementation_resource = Chef::Resource::CookbookFile.new("/preseed-file.txt")
          events.resource_action_start(implementation_resource , :create)
          events.resource_current_state_loaded(implementation_resource, :create, implementation_resource)
          events.resource_updated(implementation_resource, :create)
          events.resource_completed(implementation_resource)

          events.resource_updated(new_resource, :create)
          events.resource_completed(new_resource)
          events.converge_complete
          run_status.stop_clock
        end

        it_behaves_like "sends a converge message"
      end

      context "when the run contains a file resource that is skipped due to a block conditional" do
        let(:total_resource_count) { 1 }
        let(:updated_resource_count) { 0 }
        let(:resource_record) do
          rec = resource_record_for(current_resource, new_resource, :create, "skipped")
          rec["conditional"] = "not_if { #code block }" # FIXME: "#code block" is poor, is there some way to fix this?
          [ rec ]
        end
        let(:status) { "success" }

        before do
          conditional = (new_resource.not_if { true }).first
          events.resource_action_start(new_resource, :create)
          events.resource_current_state_loaded(new_resource, :create, current_resource)
          events.resource_skipped(new_resource, :create, conditional)
          events.resource_completed(new_resource)
          events.converge_complete
          run_status.stop_clock
        end

        it_behaves_like "sends a converge message"
      end

      context "when the run contains a file resource that is skipped due to a string conditional" do
        let(:total_resource_count) { 1 }
        let(:updated_resource_count) { 0 }
        let(:resource_record) do
          rec = resource_record_for(current_resource, new_resource, :create, "skipped")
          rec["conditional"] = 'not_if "true"'
          [ rec ]
        end
        let(:status) { "success" }

        before do
          conditional = (new_resource.not_if "true").first
          events.resource_action_start(new_resource, :create)
          events.resource_current_state_loaded(new_resource, :create, current_resource)
          events.resource_skipped(new_resource, :create, conditional)
          events.resource_completed(new_resource)
          events.converge_complete
          run_status.stop_clock
        end

        it_behaves_like "sends a converge message"
      end

      context "when the run contains a file resource that threw an exception" do
        let(:exception) { Exception.new("imperial to metric conversion error") }
        let(:error_description) { Chef::Formatters::ErrorMapper.resource_failed(new_resource, :create, exception).for_json }
        let(:total_resource_count) { 1 }
        let(:updated_resource_count) { 0 }
        let(:resource_record) do
          rec = resource_record_for(current_resource, new_resource, :create, "failed")
          rec["error_message"] = "imperial to metric conversion error"
          [ rec ]
        end
        let(:status) { "failure" }

        before do
          exception.set_backtrace(caller)
          events.resource_action_start(new_resource, :create)
          events.resource_current_state_loaded(new_resource, :create, current_resource)
          events.resource_failed(new_resource, :create, exception)
          events.resource_completed(new_resource)
          events.converge_complete
          run_status.stop_clock
          run_status.exception = exception
        end

        it_behaves_like "sends a converge message"
      end

      context "when the run contains a file resource that threw an exception in load_current_resource" do
        let(:exception) { Exception.new("imperial to metric conversion error") }
        let(:error_description) { Chef::Formatters::ErrorMapper.resource_failed(new_resource, :create, exception).for_json }
        let(:total_resource_count) { 1 }
        let(:updated_resource_count) { 0 }
        let(:resource_record) do
          rec = resource_record_for(current_resource, new_resource, :create, "failed")
          rec["before"] = {}
          rec["error_message"] = "imperial to metric conversion error"
          [ rec ]
        end
        let(:status) { "failure" }

        before do
          exception.set_backtrace(caller)
          events.resource_action_start(new_resource, :create)
          # resource_current_state_loaded is skipped
          events.resource_failed(new_resource, :create, exception)
          events.resource_completed(new_resource)
          events.converge_failed(exception)
          run_status.stop_clock
          run_status.exception = exception
        end

        it_behaves_like "sends a converge message"
      end

      context "when the resource collection contains a resource that was unproccesed due to prior errors" do
        let(:exception) { Exception.new("imperial to metric conversion error") }
        let(:error_description) { Chef::Formatters::ErrorMapper.resource_failed(new_resource, :create, exception).for_json }
        let(:total_resource_count) { 2 }
        let(:updated_resource_count) { 0 }
        let(:unprocessed_resource) do
          res = Chef::Resource::Service.new("unprocessed service")
          res.cookbook_name = cookbook_name
          res.recipe_name = recipe_name
          allow(res).to receive(:cookbook_version).and_return(cookbook_version)
          res
        end
        let(:resource_record) do
          rec1 = resource_record_for(current_resource, new_resource, :create, "failed")
          rec1["error_message"] = "imperial to metric conversion error"
          rec2 = resource_record_for(nil, unprocessed_resource, :nothing, "unprocessed")
          rec2["before"] = {}
          rec2["duration"] = "" # FIXME?: resource_completed() never called so DC does not use the elapsed_time, so we get an empty string
          [ rec1, rec2 ]
        end
        let(:status) { "failure" }

        before do
          run_context.resource_collection << new_resource
          run_context.resource_collection << unprocessed_resource
          exception.set_backtrace(caller)
          events.resource_action_start(new_resource, :create)
          events.resource_current_state_loaded(new_resource, :create, current_resource)
          events.resource_failed(new_resource, :create, exception)
          events.resource_completed(new_resource)
          new_resource.executed_by_runner = true
          events.converge_failed(exception)
          run_status.stop_clock
          run_status.exception = exception
        end

        it_behaves_like "sends a converge message"
      end

      context "when cookbook resolution fails" do
        let(:exception) { Exception.new("imperial to metric conversion error") }
        let(:error_description) { Chef::Formatters::ErrorMapper.cookbook_resolution_failed(expansion, exception).for_json }
        let(:total_resource_count) { 0 }
        let(:updated_resource_count) { 0 }
        let(:status) { "failure" }

        before do
          events.cookbook_resolution_failed(expansion, exception)
          run_status.stop_clock
          run_status.exception = exception
        end

        it_behaves_like "sends a converge message"
      end

      context "When cookbook synchronization fails" do
        let(:exception) { Exception.new("imperial to metric conversion error") }
        let(:error_description) { Chef::Formatters::ErrorMapper.cookbook_sync_failed({}, exception).for_json }
        let(:total_resource_count) { 0 }
        let(:updated_resource_count) { 0 }
        let(:status) { "failure" }

        before do
          events.cookbook_sync_failed(expansion, exception)
          run_status.stop_clock
          run_status.exception = exception
        end

        it_behaves_like "sends a converge message"
      end

    end
  end
end
