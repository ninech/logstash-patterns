# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

RSpec.describe 'puppet master log' do

  let(:pattern) { 'PUPPETMASTER' }
  let(:value) { "" }
  let(:grok) { grok_match(pattern, value) }
  let(:subject) { grok }

  describe 'parse compule time' do
    let(:value) { 'Compiled catalog for server.example.com in environment production in 1.54 seconds' }

    it { is_expected.to include('puppet_agent' => 'server.example.com') }
    it { is_expected.to include('puppet_environment' => 'production') }
    it { is_expected.to include('puppet_compile_time' => '1.54') }
  end

end
