package Test::Net::LDAP::Simple;

use base 'Test::Class';
use Test::More;
use Test::Most;

use Net::LDAP::Entry;
use Net::LDAP::Simple::User;

use Modern::Perl '2015';
use experimental qw(signatures);
no warnings qw(experimental::signatures);

sub class {'Net::LDAP::Simple::User'}

sub test_setup : Test(setup => 1) {
  my $test  = shift;
  my $entry = Net::LDAP::Entry->new();

  $entry->dn('dc=example,dc=com');
  $entry->add(givenName      => 'Arthur');
  $entry->add(sn             => 'Dent');
  $entry->add(sAMAccountName => 'adent');
  $entry->add(mail           => 'adent@example.com');

  my $user = $test->class->new(entry => $entry);

  isa_ok($user, $test->class);

  $test->{user}  = $user;
  $test->{entry} = $entry;
}

sub test_entry : Test(4) {
  my $test  = shift;
  my $entry = $test->{entry};
  my $user  = $test->{user};

  can_ok($test, 'new');
  throws_ok {$test->class->new()} qr/Missing required arguments/, 'missing argument error generated';
  throws_ok {$test->class->new(entry => undef)} qr/did not pass type constraint/, 'undef entry error generated';
  throws_ok {$user->entry($entry)} qr/Usage:/, 'can not change entry';
}

sub test_firstname : Test(3) {
  my $test  = shift;
  my $user  = $test->{user};
  my $entry = $test->{entry};

  can_ok($user, 'firstname');
  is($user->firstname, $entry->get_value('givenName'), 'firtname matches');
  throws_ok {$user->firstname('foo')} qr/read-only accessor/, 'update of firstname failed';
}

sub test_lastname : Test(3) {
  my $test  = shift;
  my $user  = $test->{user};
  my $entry = $test->{entry};

  can_ok($user, 'lastname');
  is($user->lastname, $entry->get_value('sn'), 'lastname matches');
  throws_ok {$user->lastname('foo')} qr/read-only accessor/, 'update of lastname failed';
}

sub test_username : Test(3) {
  my $test  = shift;
  my $user  = $test->{user};
  my $entry = $test->{entry};

  can_ok($user, 'username');
  is($user->username, $entry->get_value('sAMAccountName'), 'username matches');
  throws_ok {$user->username('foo')} qr/read-only accessor/, 'update of username failed';
}

sub test_email : Test(3) {
  my $test  = shift;
  my $user  = $test->{user};
  my $entry = $test->{entry};

  can_ok($user, 'email');
  is($user->email, $entry->get_value('mail'), 'email matches');
  throws_ok {$user->email('foo')} qr/read-only accessor/, 'update of email failed';
}

1;
