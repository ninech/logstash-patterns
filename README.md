# logstash-patterns
Patterns to Grok your logs

## Patterns

### dhcpd
Parse ISC DHCPD log for Package Type messages.

### dovecot
Parse Dovecot Log messages and disassemble the elements.

## Development

 1. Install dependencies with bundle
  * `bundle install --path vendor`
 2. Make sure there are no broken rspec tests
  * `bundle exec rspec`
 3. Write tests for your patterns
 4. Make sure the log line in the spec are anonymised
