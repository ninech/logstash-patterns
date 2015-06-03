# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

RSpec.describe 'amavis log' do

  let(:pattern) { 'AMAVIS' }
  let(:value) { "" }
  let(:grok) { grok_match(pattern, value) }
  let(:subject) { grok }

  describe 'passed clean' do
    let(:value) { '(42023-08) Passed CLEAN, [IPv6:2606:2800:220:1:248:1893:25c8:1946] [93.184.216.34] <from@example.com> -> <recv@example.com>, Message-ID: <1qn13030$58r39090$@example.com>, mail_id: NSiMmd5GQVho, Hits: 0.001, size: 12718, queued_as: 567424BE07C, From: <from@example.com>, X-Mailer: Microsoft_Outlook_15.0, Tests: [HTML_MESSAGE=0.001], autolearn=disabled, 4080 ms'}

    it { is_expected.to include('amavis_id' => '42023-08') }
    it { is_expected.to include('amavis_action' => 'Passed') }
    it { is_expected.to include('amavis_category' => 'CLEAN') }
    it { is_expected.to include('amavis_relay_ip' => '2606:2800:220:1:248:1893:25c8:1946') }
    it { is_expected.to include('amavis_amavis_origin_ip' => '93.184.216.34') }
    it { is_expected.to include('amavis_from' => 'from@example.com') }
    it { is_expected.to include('amavis_to' => 'recv@example.com') }
    it { is_expected.to include('amavis_message-id' => '1qn13030$58r39090$@example.com') }
    it { is_expected.to include('amavis_tests_kv' => 'HTML_MESSAGE=0.001') }
    it { is_expected.to include('amavis_elapsedtime' => '4080') }
  end

  describe 'passed bad header' do
    let(:value) { '(77162-50) Passed BAD-HEADER, [93.184.216.34] [93.184.216.34] <from@example.com> -> <recv@example.com>, quarantine: j/badh-j7ClckuQjMFG, mail_id: j7ClckuQjMFG, Hits: 5.919, size: 647762, queued_as: 9F72D6401B, From: "DHL_Paket"<from@example.com>, Tests: [ALL_TRUSTED=-1,FROM_MISSPACED=0.001,FROM_MISSP_EH_MATCH=1.065,HTML_MESSAGE=0.001], autolearn=disabled, 15291 ms' }

    it { is_expected.to include('amavis_category' => 'BAD-HEADER') }
    it { is_expected.to include('amavis_quarantine' => 'j/badh-j7ClckuQjMFG') }
    it { is_expected.to include('amavis_hits' => '5.919') }
    it { is_expected.to include('amavis_size' => '647762') }
    it { is_expected.to include('amavis_header_from' => '"DHL_Paket"<from@example.com>') }
    it { is_expected.to include('amavis_tests_kv' => 'ALL_TRUSTED=-1,FROM_MISSPACED=0.001,FROM_MISSP_EH_MATCH=1.065,HTML_MESSAGE=0.001') }
  end

  describe 'blocked spam' do
    let(:value) { '(54563-75) Blocked SPAM, [93.184.216.34] [93.184.216.34] <from@example.com> -> <recv@example.com>, quarantine: A/spam-AFLHrULq0EEe.gz, Message-ID: <1-359279491@example.com>, mail_id: AFLHrULq0EEe, Hits: 8.958, size: 5192, Subject: "Buy Spam NOW!", From: Home_Dekoration_<from@example.com>, X-Mailer: A7emailing, Tests: [DKIM_SIGNED=0.1,DKIM_VALID=-0.1,DKIM_VALID_AU=-0.1,HTML_IMAGE_RATIO_02=0.805], autolearn=disabled, 4399 ms' }

    it { is_expected.to include('amavis_action' => 'Blocked') }
    it { is_expected.to include('amavis_category' => 'SPAM') }
    it { is_expected.to include('amavis_subject' => 'Buy Spam NOW!') }
  end

  describe 'blocked infected' do
    let(:value) { '(10726-03) Blocked INFECTED (Sanesecurity.Malware.25166.AceHeur.Exe.UNOFFICIAL), [93.184.216.34] [228.139.215.98] <from@example.com> -> <recv@example.com>, quarantine: j/virus-jv4mSH43Y6S2, Message-ID: <509816331.8455820@mail.example.com>, mail_id: jv4mSH43Y6S2, Hits: -, size: 730968, Subject: "New Order", From: example_from_<from@example.comm>, 1299 ms' }

    it { is_expected.to include('amavis_category' => 'INFECTED') }
    it { is_expected.to include('amavis_match' => 'Sanesecurity.Malware.25166.AceHeur.Exe.UNOFFICIAL') }
  end
end
