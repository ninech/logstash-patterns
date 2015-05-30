# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

RSpec.describe 'dhcpd log' do

  let(:pattern) { "" }
  let(:value) { "" }
  let(:grok) { grok_match(pattern, value) }
  let(:subject) { grok }

  describe 'whole log messages' do
    let(:pattern) { 'DHCPD' }

    context 'for discover' do
      context 'direct' do
        describe 'plain' do
          let (:value) { 'DHCPDISCOVER from 00:01:02:03:04:05 via eth0' }

          it { is_expected.to include('dhcp_operation' => 'DISCOVER') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_device' => 'eth0') }
        end

        describe 'w/ device name' do
          let (:value) { 'DHCPDISCOVER from 00:01:02:03:04:05 (android-ada294ba7d9da263) via eth0' }

          it { is_expected.to include('dhcp_operation' => 'DISCOVER') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_client_name' => 'android-ada294ba7d9da263') }

          it { is_expected.to include('dhcp_device' => 'eth0') }
        end

        describe 'w/ device name and message' do
          let (:value) { 'DHCPDISCOVER from 00:01:02:03:04:05 (android-ada294ba7d9da263) via eth0: unknown network segment' }

          it { is_expected.to include('dhcp_operation' => 'DISCOVER') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_client_name' => 'android-ada294ba7d9da263') }

          it { is_expected.to include('dhcp_device' => 'eth0') }

          it { is_expected.to include('dhcpd_message' => 'unknown network segment') }
        end
      end

      context 'by relay' do
        describe 'plain' do
          let (:value) { 'DHCPDISCOVER from 00:01:02:03:04:05 via 192.168.9.9' }

          it { is_expected.to include('dhcp_operation' => 'DISCOVER') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }
        end

        describe 'w/ message' do
          let(:value) { 'DHCPDISCOVER from 00:01:02:03:04:05 via 192.168.9.9: unknown network segment' }
          
          it { is_expected.to include('dhcp_operation' => 'DISCOVER') }
          
          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }
          
          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcpd_message' => 'unknown network segment') }
        end

        describe 'w/device name and message' do
          let(:value) { 'DHCPDISCOVER from 00:01:02:03:04:05 (android-ada294ba7d9da263) via 192.168.9.9: unknown network segment' }

          it { is_expected.to include('dhcp_operation' => 'DISCOVER') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_client_name' => 'android-ada294ba7d9da263') }

          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }

          it { is_expected.to include('dhcpd_message' => 'unknown network segment') }
        end
      end
    end

    context 'for offer' do
      context 'direct' do
        describe 'plain' do
          let(:value) { 'DHCPOFFER on 192.168.9.99 to 00:01:02:03:04:05 via eth0' }
  
          it { is_expected.to include('dhcp_operation' => 'OFFER') }
  
          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }
  
          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }
  
          it { is_expected.to include('dhcp_device' => 'eth0') }
        end

        describe 'w/ client name' do
          let(:value) { 'DHCPOFFER on 192.168.9.99 to 00:01:02:03:04:05 (android-ada294ba7d9da263) via eth0' } 
  
          it { is_expected.to include('dhcp_operation' => 'OFFER') } 
  
          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') } 
  
          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') } 

          it { is_expected.to include('dhcp_client_name' => 'android-ada294ba7d9da263') }
  
          it { is_expected.to include('dhcp_device' => 'eth0') } 
        end
      end

      context 'by relay' do
        describe 'plain' do
          let(:value) { 'DHCPOFFER on 192.168.9.99 to 00:01:02:03:04:05 via 192.168.9.9' }

          it { is_expected.to include('dhcp_operation' => 'OFFER') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }
        end

        describe 'w/ client name' do
          let(:value) { 'DHCPOFFER on 192.168.9.99 to 00:01:02:03:04:05 (android-ada294ba7d9da263) via 192.168.9.9' }
  
          it { is_expected.to include('dhcp_operation' => 'OFFER') }
  
          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }
  
          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_client_name' => 'android-ada294ba7d9da263') }
  
          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }
        end
      end
    end

    context 'for request' do
      context 'direct' do
        describe 'plain' do
          let(:value) { 'DHCPREQUEST for 192.168.9.99 from 00:01:02:03:04:05 via eth0' }

          it { is_expected.to include('dhcp_operation' => 'REQUEST') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_device' => 'eth0') }
        end

        describe 'w/ client name' do
          let(:value) { 'DHCPREQUEST for 192.168.9.99 from 00:01:02:03:04:05 (android-ada294ba7d9da263) via eth0' }

          it { is_expected.to include('dhcp_operation' => 'REQUEST') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_client_name' => 'android-ada294ba7d9da263') }

          it { is_expected.to include('dhcp_device' => 'eth0') }
        end

        describe 'w/ server ip and client name' do
          let(:value) { 'DHCPREQUEST for 192.168.9.99 (192.168.9.9) from 00:01:02:03:04:05 (android-ada294ba7d9da263) via eth0' }

          it { is_expected.to include('dhcp_operation' => 'REQUEST') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_server_ip' => '192.168.9.9') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_client_name' => 'android-ada294ba7d9da263') }

          it { is_expected.to include('dhcp_device' => 'eth0') }
        end
      end

      context 'by relay' do
        describe 'plain' do
          let(:value) { 'DHCPREQUEST for 192.168.9.99 from 00:01:02:03:04:05 via 192.168.9.9' }

          it { is_expected.to include('dhcp_operation' => 'REQUEST') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }
        end

        describe 'w/ client name' do
          let(:value) { 'DHCPREQUEST for 192.168.9.99 from 00:01:02:03:04:05 (android-ada294ba7d9da263) via 192.168.9.9' }

          it { is_expected.to include('dhcp_operation' => 'REQUEST') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_client_name' => 'android-ada294ba7d9da263') }

          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }
        end

        describe 'w/ server ip and client name' do
          let(:value) { 'DHCPREQUEST for 192.168.9.99 (192.168.9.9) from 00:01:02:03:04:05 (android-ada294ba7d9da263) via 192.168.9.9' }

          it { is_expected.to include('dhcp_operation' => 'REQUEST') } 

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_server_ip' => '192.168.9.9') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') } 

          it { is_expected.to include('dhcp_client_name' => 'android-ada294ba7d9da263') } 

          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }
        end
      end
    end

    context 'for decline' do
      context 'direct' do
        describe 'w/ message' do
          let(:value) { 'DHCPDECLINE of 192.168.9.99 from 00:01:02:03:04:05 via eth0: not found' }

          it { is_expected.to include('dhcp_operation' => 'DECLINE') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_device' => 'eth0') }

          it { is_expected.to include('dhcpd_message' => 'not found') }
        end

        describe 'w/ client name and message' do
          let(:value) { 'DHCPDECLINE of 192.168.9.99 from 00:01:02:03:04:05 (android-ada294ba7d9da263) via eth0: not found' }

          it { is_expected.to include('dhcp_operation' => 'DECLINE') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_client_name' => 'android-ada294ba7d9da263') }

          it { is_expected.to include('dhcp_device' => 'eth0') }

          it { is_expected.to include('dhcpd_message' => 'not found') }
        end
      end

      context 'via relay' do
        describe 'w/ message' do
          let(:value) { 'DHCPDECLINE of 192.168.9.99 from 00:01:02:03:04:05 via 192.168.9.9: not found' }

          it { is_expected.to include('dhcp_operation' => 'DECLINE') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }

          it { is_expected.to include('dhcpd_message' => 'not found') }
        end

        describe 'w/ client name and message' do
          let(:value) { 'DHCPDECLINE of 192.168.9.99 from 00:01:02:03:04:05 (android-ada294ba7d9da263) via 192.168.9.9: not found' }

          it { is_expected.to include('dhcp_operation' => 'DECLINE') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_client_name' => 'android-ada294ba7d9da263') }

          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }

          it { is_expected.to include('dhcpd_message' => 'not found') }
        end
      end
    end

    context 'for ack' do
      context 'direct' do
        describe 'plain' do
          let(:value) { 'DHCPACK on 192.168.9.99 to 00:01:02:03:04:05 via eth0' }

          it { is_expected.to include('dhcp_operation' => 'ACK') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_device' => 'eth0') }
        end

        describe 'w/ client name' do
          let(:value) { 'DHCPACK on 192.168.9.99 to 00:01:02:03:04:05 (android-ada294ba7d9da263) via eth0' }

          it { is_expected.to include('dhcp_operation' => 'ACK') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_client_name' => 'android-ada294ba7d9da263') }

          it { is_expected.to include('dhcp_device' => 'eth0') }
        end
      end

      context 'by relay' do
        describe 'plain' do
          let(:value) { 'DHCPACK on 192.168.9.99 to 00:01:02:03:04:05 via 192.168.9.9' }

          it { is_expected.to include('dhcp_operation' => 'ACK') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }
        end

        describe 'w/ client name' do
          let(:value) { 'DHCPACK on 192.168.9.99 to 00:01:02:03:04:05 (android-ada294ba7d9da263) via 192.168.9.9' }

          it { is_expected.to include('dhcp_operation' => 'ACK') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_client_name' => 'android-ada294ba7d9da263') }

          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }
        end
      end
    end

    context 'for nack' do
      context 'direct' do
        describe 'plain' do
          let(:value) { 'DHCPNACK on 192.168.9.99 to 00:01:02:03:04:05 via eth0' }

          it { is_expected.to include('dhcp_operation' => 'NACK') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_device' => 'eth0') }
        end

        describe 'w/ client name' do
          let(:value) { 'DHCPNACK on 192.168.9.99 to 00:01:02:03:04:05 (android-ada294ba7d9da263) via eth0' }

          it { is_expected.to include('dhcp_operation' => 'NACK') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_client_name' => 'android-ada294ba7d9da263') }

          it { is_expected.to include('dhcp_device' => 'eth0') }
        end
      end

      context 'by relay' do
        describe 'plain' do
          let(:value) { 'DHCPNACK on 192.168.9.99 to 00:01:02:03:04:05 via 192.168.9.9' }

          it { is_expected.to include('dhcp_operation' => 'NACK') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }
        end

        describe 'w/ client name' do
          let(:value) { 'DHCPNACK on 192.168.9.99 to 00:01:02:03:04:05 (android-ada294ba7d9da263) via 192.168.9.9' }

          it { is_expected.to include('dhcp_operation' => 'NACK') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_client_name' => 'android-ada294ba7d9da263') }

          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }
        end
      end
    end

    context 'for release' do
      context 'direct' do
        describe 'found' do
          let(:value) { 'DHCPRELEASE of 192.168.9.99 from 00:01:02:03:04:05 via eth0 (found)' }

          it { is_expected.to include('dhcp_operation' => 'RELEASE') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_device' => 'eth0') }

          it { is_expected.to include('dhcpd_release' => 'found') }
        end

        describe 'not found' do
          let(:value) { 'DHCPRELEASE of 192.168.9.99 from 00:01:02:03:04:05 via eth0 (not found)' }

          it { is_expected.to include('dhcp_operation' => 'RELEASE') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }

          it { is_expected.to include('dhcp_device' => 'eth0') }

          it { is_expected.to include('dhcpd_release' => 'not found') }
        end
      end

      context 'by relay' do
        describe 'found' do
          let(:value) { 'DHCPRELEASE of 192.168.9.99 from 00:01:02:03:04:05 via 192.168.9.9 (found)' }
  
          it { is_expected.to include('dhcp_operation' => 'RELEASE') }
  
          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }
  
          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }
  
          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }
  
          it { is_expected.to include('dhcpd_release' => 'found') }
        end
  
        describe 'not found' do
          let(:value) { 'DHCPRELEASE of 192.168.9.99 from 00:01:02:03:04:05 via 192.168.9.9 (not found)' }
  
          it { is_expected.to include('dhcp_operation' => 'RELEASE') }
  
          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }
  
          it { is_expected.to include('dhcp_client_mac' => '00:01:02:03:04:05') }
  
          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }
  
          it { is_expected.to include('dhcpd_release' => 'not found') }
        end
      end
    end

    context 'for inform' do
      context 'direct' do
        describe 'plain' do
          let(:value) { 'DHCPINFORM from 192.168.9.99 via eth0' }

          it { is_expected.to include('dhcp_operation' => 'INFORM') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_device' => 'eth0') }
        end

        describe 'w/ message' do
          let(:value) { 'DHCPINFORM from 192.168.9.99 via eth0: unknown subnet for client address 192.168.9.9' }

          it { is_expected.to include('dhcp_operation' => 'INFORM') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_device' => 'eth0') }

          it { is_expected.to include('dhcpd_message' => 'unknown subnet for client address 192.168.9.9') }
        end
      end

      context 'by relay' do
        describe 'found' do
          let(:value) { 'DHCPINFORM from 192.168.9.99 via 192.168.9.9' }

          it { is_expected.to include('dhcp_operation' => 'INFORM') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }
        end

        describe 'not found' do
          let(:value) { 'DHCPINFORM from 192.168.9.99 via 192.168.9.9: unknown subnet for client address 192.168.9.9' }

          it { is_expected.to include('dhcp_operation' => 'INFORM') }

          it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

          it { is_expected.to include('dhcp_relay_ip' => '192.168.9.9') }

          it { is_expected.to include('dhcpd_message' => 'unknown subnet for client address 192.168.9.9') }
        end
      end
    end

    context 'for leasequery' do
      describe 'w/ ip' do
        let(:value) { 'DHCPLEASEQUERY from 192.168.9.99 for IP 192.168.9.99' }

        it { is_expected.to include('dhcp_operation' => 'LEASEQUERY') }

        it { is_expected.to include('dhcp_leasequery_ip' => '192.168.9.99') }
      end

      describe 'w/ client-id' do
        let(:value) { 'DHCPLEASEQUERY from 192.168.9.99 for client-id 0xabc' }

        it { is_expected.to include('dhcp_operation' => 'LEASEQUERY') }

        it { is_expected.to include('dhcp_leasequery_id' => '0xabc') }
      end

      describe 'w/ mac' do
        let(:value) { 'DHCPLEASEQUERY from 192.168.9.99 for MAC address 00:01:02:03:04:05' }

        it { is_expected.to include('dhcp_operation' => 'LEASEQUERY') }

        it { is_expected.to include('dhcp_leasequery_mac' => '00:01:02:03:04:05') }
      end

      describe 'anwser unknown' do
        let(:value) { 'DHCPLEASEUNKNOWN to 192.168.9.99 for IP 192.168.9.99 (1 associated IPs)' }

        it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

        it { is_expected.to include('dhcp_leasequery_ip' => '192.168.9.99') }

        it { is_expected.to include('dhcp_leasequery_associated' => '1') }
      end
      describe 'anwser active' do
        let(:value) { 'DHCPLEASEACTIVE to 192.168.9.99 for client-id 0xabc (2 associated IPs)' }

        it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

        it { is_expected.to include('dhcp_leasequery_id' => '0xabc') }

        it { is_expected.to include('dhcp_leasequery_associated' => '2') }
      end
      describe 'anwser unasigned' do
        let(:value) { 'DHCPLEASEUNASSIGNED to 192.168.9.99 for MAC address 00:01:02:03:04:05 (3 associated IPs)' }

        it { is_expected.to include('dhcp_client_ip' => '192.168.9.99') }

        it { is_expected.to include('dhcp_leasequery_mac' => '00:01:02:03:04:05') }

        it { is_expected.to include('dhcp_leasequery_associated' => '3') }
      end
    end
  end
end
