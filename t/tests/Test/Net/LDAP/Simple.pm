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
  $File::ShareDir::DIST_SHARE{'Net-LDAP-Simple'} = "$FindBin::Bin/../share";
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


sub binddn  {return $ENV{LDAP_BINDDN} // 'foo';}
sub bindpw  {return $ENV{LDAP_BINDPW} // '12345';}
sub host    {return $ENV{LDAP_HOST}   // 'localhost';}
sub passwd  {return $ENV{LDAP_PASSWORD};}
sub user    {return $ENV{USER};}
sub class   {return 'Net::LDAP::Simple';}
sub fixture {return "$FindBin::Bin/../t/fixtures/config.pl"}

sub setup : Test(no_plan) {
  my $test = shift;
  my $ldap = $test->class->new(
    binddn => $test->binddn,
    bindpw => $test->bindpw,
    host   => $test->host,
  );

  isa_ok($ldap, $test->class);

  $test->{ldap} = $ldap;
}

sub test_roles : Test(no_plan) {
  my $test    = shift;
  my $ldap    = $test->{ldap};
  my $fixture = $test->{fixture};

  can_ok($ldap, (qw(has_role add_role)));

  for (keys %FIXTURE_ROLES) {
    ok($ldap->add_role($_ => $FIXTURE_ROLES{$_}), "added $_ role");
  }

  ok($ldap->has_role('hr'), 'HR role exists');
  ok($ldap->has_role('foo_editors'), 'Editors role exists');
}

sub test_search : Test(no_plan) {
  ok(1);
}

sub test_conn : Test(no_plan) {
  ok(1);
}

1;

__END__

sub startup : Test(startup => 3) {
  my $test = shift;

  if ($ENV{TEST_LDAP_PASSWORD}) {
    print STDERR 'AD Password: ';
    system 'stty -echo';
    chomp(my $input = <STDIN>);
    system 'stty echo';
    print "\n";

    $test->{password} = $input;
  }

  ok($test->binddn, 'binddn set') or die 'binddn is required, set env var $LDAP_BINDDN';
  ok($test->bindpw, 'bindpw set') or die 'bindpw is required, set env var $LDAP_BINDPW';
  ok($test->host,   'host set')   or die 'host is required, set env var $LDAP_HOST';
}

sub setup : Test(setup => 6) {
  my $test         = shift;
  my $fixture_data = do $test->fixture;

  my $ldap = $test->class->new(
    binddn => $test->binddn,
    bindpw => $test->bindpw,
    host   => $test->host,
  );

  isa_ok($ldap,       $test->class);
  isa_ok($ldap->conn, 'Net::LDAP');

  can_ok($ldap, (qw(has_role get_role add_role roles)));

  for my $role (keys %{$fixture_data->{roles}}) {
    ok($ldap->add_role($role => $fixture_data->{roles}->{$role}), "added $role role");
  }

  $test->{fixture_data} = $fixture_data;
  $test->{ldap}         = $ldap;

  return;
}

sub teardown : Test(teardown) {
  my $test = shift;

  $test->{ldap}->unbind;
  $test->{ldap} = undef;

  return;
}

sub test_check : Test(11) {
  my $test = shift;
  my $ldap = $test->{ldap};

  # NOTE: [06/14/2020 schelcj] - anything over 5 attempts will result in you locking your AD acount for ~15min
  for (1..5) {
    my $pass = random_string('........');

    is($ldap->check(user => 'foo', pass => $pass), $FALSE, 'authentication failed for foo');
    is($ldap->check(user => $test->user, pass => $pass), $FALSE, 'invalid password for ' . $test->user);
  }

  return unless $test->{passwd};
  is($ldap->check(user => $test->user, pass => $test->{passwd}), $TRUE, 'authenticated ' . $test->user);

  return;
}

sub test_roles : Test(4) {
  my $test  = shift;
  my $ldap  = $test->{ldap};
  my $roles = $test->{fixture_data}->{roles};

  for my $role (keys %{$roles}) {
    ok($ldap->has_role($role), "ldap object has role '$role'");
  }

  is($ldap->has_role('foo'), '', q{ldap object does not have role 'foo'});

  return;
}

sub test_is_role : Test(9) {
  my $test  = shift;
  my $ldap  = $test->{ldap};
  my $users = $test->{fixture_data}->{users};

  for my $role (keys %{$users}) {
    for my $user (@{$users->{$role}}) {
      ok($ldap->is_role(user => $user, role => $role), "user '$user' belongs to role '$role'");
    }
  }

  ok(!$ldap->is_role(user => $test->user, role => 'hr'), qq{user '@{[ $test->user ]}' does not have role 'hr'});

  return;
}

sub test_ad_timeout : Test(1) {
  return 'not testing AD timeout' unless $ENV{TEST_AD_TIMEOUT};

  my $test  = shift;
  my $ldap  = $test->{ldap};
  my $sleep = 30 * 60;

  note "Get comfortale we are going to wait for AD to timeout, sleeping for $sleep seconds";

  sleep $sleep;

  ok($ldap->lookup_user(user => $test->user), 'can still lookup user');

  return;
}

sub test_get_user : Test(5) {
  return 'not testing user gecos' unless $ENV{TEST_LDAP_USER};

  my $test = shift;
  my $ldap = $test->{ldap};

  can_ok($ldap, 'get_user');
  my $user = $ldap->get_user(user => $test->user);

  can_ok($user, (qw(firstname lastname)));

  # NOTE: [06/10/2020 schelcj] - a bit of a cheat but since our gecos comes from AD
  # this will match what we get out of ldap and will work for our names but not
  # any future devs with middle initial or name in their gecos. 
  my $gecos = getpwnam($test->user)->gecos;
  my ($fullname) = split(/,/, $gecos);
  my ($firstname, $lastname) = split(/\s/, $fullname);

  is($user->firstname, $firstname,  'first name is correct');
  is($user->lastname,  $lastname,   'last name is correct');
  is($user->username,  $test->user, 'username is correct');
}

1;
