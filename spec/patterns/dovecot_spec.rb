# encoding: utf-8
require "spec_helper"
require "logstash/patterns/core"

RSpec.describe "DOVECOT" do

  let(:pattern) { "" }
  let(:value) { "" }
  let(:grok) { grok_match(pattern, value) }

  describe "DOVECOT_PROGRAM" do

    let(:pattern) { "DOVECOT_PROGRAM" }
    let(:value) { "pop3-login: Login: user=<mail@example.com>, method=PLAIN, rip=10.11.12.13, lip=192.168.9.9, mpid=13559" }
  
    it "a pattern pass the grok expression" do
      expect(grok).to pass
    end
  
    it "matches a simple message" do
      expect(subject).to match(value)
    end
  
    it "generates the dovecot_program field" do
      expect(grok).to include("dovecot_program" => "pop3-login")
    end
  
    context "dovecot program with username" do
      let(:value) { "imap(mail@example.com): Disconnected: Logged out bytes=512/1024" }
  
      it "generates the dovecot_user field" do
        expect(grok).to include("dovecot_user" => "mail@example.com")
      end
    end
  end
  
  describe "DOVECOT_LIP" do
    let(:pattern) { "DOVECOT_LIP" }
    let(:value) { "pop3-login: Login: user=<mail@example.com>, method=PLAIN, rip=10.11.12.13, lip=192.168.9.9, mpid=13559" }
  
    it "generates the dovecot_local_ip field" do
      expect(grok).to include("dovecot_local_ip" => "192.168.9.9")
    end
  end
  
  describe "DOVECOT_RIP" do
    let(:pattern) { "DOVECOT_RIP" }
    let(:value) { "pop3-login: Login: user=<mail@example.com>, method=PLAIN, rip=10.11.12.13, lip=192.168.9.9, mpid=13559" }
  
    it "generates the dovecot_remote_ip field" do
      expect(grok).to include("dovecot_remote_ip" => "10.11.12.13")
    end
  end
  
  describe "DOVECOT_METHOD" do
    let(:pattern) { "DOVECOT_METHOD" }
    let(:value) { "pop3-login: Login: user=<mail@example.com>, method=PLAIN, rip=10.11.12.13, lip=192.168.9.9, mpid=13559" }
  
    it "generates the dovecot_method field" do
      expect(grok).to include("dovecot_method" => "PLAIN")
    end
  end
  
  describe "DOVECOT_MPID" do
    let(:pattern) { "DOVECOT_MPID" }
    let(:value) { "pop3-login: Login: user=<mail@example.com>, method=PLAIN, rip=10.11.12.13, lip=192.168.9.9, mpid=13559" }
  
    it "generates the dovecot_mpid field" do
      expect(grok).to include("dovecot_mpid" => "13559")
    end
  end

  describe "DOVECOT_USER" do
    let(:pattern) { "DOVECOT_USER" }
    let(:value) { "pop3-login: Login: user=<mail@example.com>, method=PLAIN, rip=10.11.12.13, lip=192.168.9.9, mpid=13559" }

    it "generates the dovecot_user field" do
      expect(grok).to include("dovecot_user" => "mail@example.com")
    end
  end

  describe "DOVECOT_BYTES" do
    let(:pattern) { "DOVECOT_BYTES" }
    let(:value) { "imap(mail@example.com): Disconnected: Logged out bytes=883/7504" }

    it "generates the dovecot_bytes_in field" do
      expect(grok).to include("dovecot_bytes_in" => "883")
    end

    it "generates the dovecot_bytes_in field" do
      expect(grok).to include("dovecot_bytes_out" => "7504")
    end
  end

  describe "DOVECOT_TOP" do
    let(:pattern) { "DOVECOT_TOP" }
    let(:value) { "pop3(mail@example.com): Disconnected: Logged out top=1/21, retr=2/42, del=3/23, size=16978739" }

    it "generates the dovecot_cmd_top field" do
      expect(grok).to include("dovecot_cmd_top" => "1")
    end

    it "generates the dovecot_bytes_top field" do
      expect(grok).to include("dovecot_bytes_top" => "21")
    end
  end

  describe "DOVECOT_RETR" do
    let(:pattern) { "DOVECOT_RETR" }
    let(:value) { "pop3(mail@example.com): Disconnected: Logged out top=1/21, retr=2/42, del=3/23, size=16978739" }

    it "generates the dovecot_cmd_retr field" do
      expect(grok).to include("dovecot_cmd_retr" => "2")
    end

    it "generates the dovecot_bytes_retr field" do
      expect(grok).to include("dovecot_bytes_retr" => "42")
    end
  end

  describe "DOVECOT_DEL" do
    let(:pattern) { "DOVECOT_DEL" }
    let(:value) { "pop3(mail@example.com): Disconnected: Logged out top=1/21, retr=2/42, del=3/23, size=16978739" }

    it "generates the dovecot_cmd_del field" do
      expect(grok).to include("dovecot_cmd_del" => "3")
    end

    it "generates the dovecot_message_count" do
      expect(grok).to include("dovecot_message_count" => "23")
    end
  end

  describe "DOVECOT_SIZE" do
    let(:pattern) { "DOVECOT_SIZE" }
    let(:value) { "pop3(mail@example.com): Disconnected: Logged out top=1/21, retr=2/42, del=3/23, size=16978739" }
    
    it "generates the dovecot_size" do
      expect(grok).to include("dovecot_size" => "16978739")
    end
  end

  describe "DOVECOT_SSL_SECURITY" do

    let(:pattern) { "DOVECOT_SSL_SECURITY" }
    let(:value) { "pop3-login: Login: user=<mail@example.com>, method=PLAIN, rip=10.11.12.13, lip=192.168.9.9, mpid=13559, ssl_security=\"TLSv1.3 with cipher DHE-RSA-AES256-SHA (256/256 bits)\"" }

    it "generates the dovecot_ssl_proto field" do
      expect(grok).to include("dovecot_ssl_proto" => "TLSv1.3")
    end

    it "generates the dovecot_ssl_cipher field" do
      expect(grok).to include("dovecot_ssl_cipher" => "DHE-RSA-AES256-SHA (256/256 bits)")
    end
  end


  describe "DOVECOT_ELEMENTS" do
    let(:pattern) { "DOVECOT_ELEMENTS" }

    context "pop3-login" do
      let(:value) { "pop3-login: Login: user=<mail@example.com>, method=PLAIN, rip=10.11.12.13, lip=192.168.9.9, mpid=13559" }

      it "generates the dovecot_local_ip field" do
        expect(grok).to include("dovecot_local_ip" => "192.168.9.9")
      end

      it "generates the dovecot_remote_ip field" do
        expect(grok).to include("dovecot_remote_ip" => "10.11.12.13")
      end

      it "generates the dovecot_method field" do
        expect(grok).to include("dovecot_method" => "PLAIN")
      end

      it "generates the dovecot_mpid field" do
        expect(grok).to include("dovecot_mpid" => "13559")
      end

      it "generates the dovecot_user field" do
        expect(grok).to include("dovecot_user" => "mail@example.com")
      end
    end

    context "pop3" do
      let(:value) { "pop3(mail@example.com): Disconnected: Logged out top=1/21, retr=2/42, del=3/23, size=16978739" }

      it "generates the dovecot_cmd_top field" do
        expect(grok).to include("dovecot_cmd_top" => "1")
      end
  
      it "generates the dovecot_bytes_top field" do
        expect(grok).to include("dovecot_bytes_top" => "21")
      end
  
      it "generates the dovecot_cmd_retr field" do
        expect(grok).to include("dovecot_cmd_retr" => "2")
      end
  
      it "generates the dovecot_bytes_retr field" do
        expect(grok).to include("dovecot_bytes_retr" => "42")
      end
  
      it "generates the dovecot_cmd_del field" do
        expect(grok).to include("dovecot_cmd_del" => "3")
      end
  
      it "generates the dovecot_message_count" do
        expect(grok).to include("dovecot_message_count" => "23")
      end

      it "generates the dovecot_size" do
        expect(grok).to include("dovecot_size" => "16978739")
      end
    end

    context "imap" do
      let(:value) { "imap(mail@example.com): Disconnected: Logged out bytes=883/7504" }

      it "generates the dovecot_bytes_in field" do
        expect(grok).to include("dovecot_bytes_in" => "883")
      end

      it "generates the dovecot_bytes_in field" do
        expect(grok).to include("dovecot_bytes_out" => "7504")
      end
    end
  end

  describe "DOVECOT" do
    let(:pattern) { "DOVECOT" }

    let(:value) { "pop3(mail@example.com): Disconnected: Logged out top=1/21, retr=2/42, del=3/23, size=16978739" }

    it "generates the dovecot_cmd_top field" do
      expect(grok).to include("dovecot_cmd_top" => "1")
    end
 
    it "generates the dovecot_bytes_top field" do
      expect(grok).to include("dovecot_bytes_top" => "21")
    end
 
    it "generates the dovecot_cmd_retr field" do
      expect(grok).to include("dovecot_cmd_retr" => "2")
    end
 
    it "generates the dovecot_bytes_retr field" do
      expect(grok).to include("dovecot_bytes_retr" => "42")
    end
 
    it "generates the dovecot_cmd_del field" do
      expect(grok).to include("dovecot_cmd_del" => "3")
    end
 
    it "generates the dovecot_message_count" do
      expect(grok).to include("dovecot_message_count" => "23")
    end
 
    it "generates the dovecot_size" do
      expect(grok).to include("dovecot_size" => "16978739")
    end

    it "generates the dovecot_message" do
      expect(grok).to include("dovecot_message" => "Disconnected: Logged out")
    end
  end
end
