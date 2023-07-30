package Test::Net::LDAP::Simple;

use base 'Test::Class';

use Const::Fast;
use Data::Dumper;
use FindBin;
use User::pwent;
use String::Random qw(random_string);
use Test::More;
use Test::Most;

use Net::LDAP::Simple;

use Modern::Perl '2015';
use experimental qw(signatures);
no warnings qw(experimental::signatures);

BEGIN {
  $File::ShareDir::DIST_SHARE{'Net-LDAP-Simple'} = $FindBin::Bin;
}

const my $TRUE  => 1;
const my $FALSE => 0;
const my %FIXTURE_ROLES => (
  foo_editors => [qw(FOOAccess editors)],
  hr          => ['HR'],
);
const my %FIXTURE_USERS => (
  foo_editors => [qw(schelcj)],
  hr          => [qw(bob alice)],
);

sub binddn             {return $ENV{LDAP_BINDDN} // 'foo';}
sub bindpw             {return $ENV{LDAP_BINDPW} // '12345';}
sub host               {return $ENV{LDAP_HOST}   // 'localhost';}
sub passwd             {return $ENV{LDAP_PASSWORD};}
sub user               {return $ENV{USER};}
sub class              {return 'Net::LDAP::Simple';}
sub has_server ($test) {return $test->host ne 'localhost';}

sub setup : Test(setup => 1) ($test) {
  $test->{ldap} = $test->class->new(
    binddn => $test->binddn,
    bindpw => $test->bindpw,
    host   => $test->host,
  );

  isa_ok($test->{ldap}, $test->class);
}

sub teardown : Test(teardown => 2) ($test) {
  can_ok($test->{ldap}, 'unbind');
  ok($test->{ldap}->unbind, 'unbind success');
  $test->{ldap} = undef;
}

sub test_roles : Test(5) ($test) {
  my $ldap = $test->{ldap};

  can_ok($ldap, (qw(has_role add_role)));

  for (keys %FIXTURE_ROLES) {
    ok($ldap->add_role($_ => $FIXTURE_ROLES{$_}), "added $_ role");
  }

  ok($ldap->has_role('hr'),          'HR role exists');
  ok($ldap->has_role('foo_editors'), 'Editors role exists');
}

# TODO: [07/15/2023 schelcj] - finish
sub test_conf : Test(no_plan) {
  # TODO: [06/28/2023 schelcj] - test loading a config file
  # TODO: [06/28/2023 schelcj] - test setting up config from just attrs
}

sub test_search : Test(6) ($test) {
  return 'testing without an ldap server' unless $test->has_server;
  my $ldap = $test->{ldap};
  can_ok($ldap, 'search');

  my $search;
  lives_ok {
    $search = $ldap->search(
      base   => $ldap->user_basedn,
      scope  => $ldap->user_scope,
      filter => $ldap->_user_filter('tesla')
    );
  }
  'search was successfull';

  throws_ok {
    $ldap->search();
  }
  'Net::LDAP::Simple::Exceptions::FailedSearch', 'throws failed search exception';

  isa_ok($search, 'Net::LDAP::Search');
  is($search->count,                        1,                         'found a single record');
  is($search->pop_entry->get_value('mail'), 'tesla@ldap.forumsys.com', 'email matches');
}

sub test_lookup_user : Test(5) ($test) {
  return 'testing without an ldap server' unless $test->has_server;

  my $ldap = $test->{ldap};
  can_ok($ldap, 'lookup_user');
  ok(!$ldap->lookup_user(user => undef), 'undef user lookup returned false');
  ok(!$ldap->lookup_user(user => 'foo'), 'user lookup for non-existant user return false');
  ok(my $user = $ldap->lookup_user(user => 'tesla'), 'user lookup found Tesla');
  isa_ok($user, 'Net::LDAP::Entry');
}

sub test_check : Test(6) ($test) {
  return 'testing without an ldap server' unless $test->has_server;

  my $ldap = $test->{ldap};
  can_ok($ldap, 'check');
  ok($ldap->check(user  => 'euclid', pass => 'password'), 'user authen check passed');
  ok(!$ldap->check(user => 'euclid', pass => 'foo'),      'user authen check failed as expected');
  ok(!$ldap->check(user => undef,    pass => undef),      'no user or pass failed');
  ok(!$ldap->check(user => undef,    pass => 'foo'),      'pass defined but no no user defined failed');
  ok(!$ldap->check(user => 'cooper', pass => '12345'),    'Sheldon is not a user');
}

sub test_is_role : Test(5) ($test) {
  return 'testing without an ldap server' unless $test->has_server;
  my $ldap = $test->{ldap};

  can_ok($ldap, 'is_role');
  ok($ldap->add_role(scientist => [qw(scientists italians)]), 'added roles');
  ok($ldap->has_role('scientist'),                            'Scientist role was defined');
  ok($ldap->lookup_user(user => 'tesla'),                     'Tesla user was found');
  ok($ldap->is_role(user => 'tesla', role => 'scientist'),    'Tesla is a scientist');
}

sub test_get_user : Test(no_plan) ($test) {
  return 'testing without an ldap server' unless $test->has_server;

  my $ldap = $test->{ldap};
  can_ok($ldap, 'get_user');
  ok(!$ldap->get_user(user => undef), 'Undef user works?');
  ok(my $user = $ldap->get_user(user => 'tesla'), 'Found user for Tesla');
  isa_ok($user, $test->class . '::User');
}

sub test_ad_timeout : Test(1) ($test) {
  return 'not testing AD timeout' unless $ENV{TEST_AD_TIMEOUT};

  my $ldap  = $test->{ldap};
  my $sleep = 30 * 60;

  note "Get comfortale we are going to wait for AD to timeout, sleeping for $sleep seconds";

  sleep $sleep;

  ok($ldap->lookup_user(user => $test->user), 'can still lookup user');

  return;
}

1;
