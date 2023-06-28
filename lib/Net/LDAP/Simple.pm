package Net::LDAP::Simple;

# ABSTRACT: This module provides a, hopefully, simple interface to an Active Directory LDAP structure to make authorization decisions based on group, aka role, membership.

=head1 SYNOPSIS

    my $ldap = Net::LDAP::Simple->new(
      binddn => 'foo',
      bindpw => '12345',
      host   => 'ldap.example.com',
    );

    $ldap->add_role(editors => [qw(Access editors)]);

    if ($ldap->is_role(user => 'foo', role => 'editors')) {
        # YAY they have access
    } else {
        # UH OH, no access for this person
    }


=cut
use Carp;
use Const::Fast;
use English qw(-no_match_vars);
use File::ShareDir 'dist_file';
use Moo;
use Net::LDAP;
use Net::LDAP::Simple::Exceptions;
use Net::LDAP::Simple::User;
use Syntax::Keyword::Try;
use Types::Standard qw(ArrayRef HashRef InstanceOf Str);
use namespace::autoclean;

use Modern::Perl '2015';
use experimental qw(signatures);
no warnings qw(experimental::signatures);

const my $TRUE              => 1;
const my $FALSE             => 0;
const my $COMMA             => ',';
const my $MAX_AUTH_ATTEMPTS => 5;
const my $CONN_RESET_REGEXP => qr/connection reset by peer/i;

# TODO: [06/10/2020 schelcj]
#   - what to do with unknown errors in the same context?
#   - do we even care what the actual issue is and just want to bail in security issues?
#
# AcceptSecurityContext error, data 525 : User not found
# AcceptSecurityContext error, data 52e : Invalid credentials
# AcceptSecurityContext error, data 530 : Not permitted to logon at this time
# AcceptSecurityContext error, data 531 : Not permitted to logon from this workstation
# AcceptSecurityContext error, data 532 : Password expired
# AcceptSecurityContext error, data 533 : Account disabled
# AcceptSecurityContext error, data 701 : Account expired
# AcceptSecurityContext error, data 773 : User must reset password
# AcceptSecurityContext error, data 775 : Account locked out
const my $AUTH_FAIL_REGEXP => qr/AcceptSecurityContext error, data (?:525|52e|530|531|532|533|701|773|775)/i;

=method new(%params)

Instantiate new Net::LDAP::Simple object


Defaults loaded from a config packaged with this module.

  @PARAMS: %params
    (
      role_basedn => string,
      role_field  => string,
      role_filter => string,
      role_scope  => string,
      user_basedn => string,
      user_filter => string,
      user_scope  => string,
    )

=over 2

=item B<binddn>

  Username to bind to the LDAP server (ActiveDirectory)
  Default: undef
  Required: true

=item B<bindpw>

  Password to bind to the LDAP server with
  Default: undef
  Required: true

=item B<ldap_server> 

  Hostname of LDAP server
  Default: undef
  Required: true

=item B<role_base>

  The base LDAP dn for searching for groups/roles.
  Default: OU=Groups,DC=example,DC=com

=item B<role_filter>

  A sprintf() format string of the member search.
  Default: member=CN=%s,OU=Users,dc=example,dc=com 

=item B<role_scope>

  Scope of the ldap search. Defaults to searching the subtree below the start.
  Default: sub

=item B<user_basedn>

  Base DN search path.
  Default: DC=example,DC=com

=item B<user_filter>

  Filter to search for users by sAMAccountName.
  Default: (&(objectClass=User)(sAMAccountName=%s))

=item B<user_scope>

  Scope of ldap search. Defaults to searching the subtree below the start.
  Default: sub

=back
=cut
has '_roles' => (
  is      => 'rwp',
  isa     => HashRef[ArrayRef],
  default => sub {{}},
);

has '_role_map' => (
  is      => 'ro',
  isa     => HashRef,
  lazy    => 1,
  builder => '_build__role_map',
);

has '_file' => (
  is      => 'ro',
  isa     => Str,
  lazy    => 1,
  builder => '_build__file',
);

has '_conf' => (
  is      => 'ro',
  isa     => HashRef,
  lazy    => 1,
  builder => '_build__conf',
);

has 'host' => (
  is       => 'ro',
  isa      => Str,
  required => 1,
);

has 'user_basedn' => (
  is      => 'ro',
  isa     => Str,
  lazy    => 1,
  builder => '_build_user_basedn',
);

has 'binddn' => (
  is       => 'ro',
  isa      => Str,
  required => 1,
);

has 'bindpw' => (
  is       => 'ro',
  isa      => Str,
  required => 1,
);

has 'user_scope' => (
  is      => 'ro',
  isa     => Str,
  lazy    => 1,
  builder => '_build_user_scope',
);

has 'role_scope' => (
  is      => 'ro',
  isa     => Str,
  lazy    => 1,
  builder => '_build_role_scope',
);

has 'role_field' => (
  is      => 'ro',
  isa     => Str,
  lazy    => 1,
  builder => '_build_role_field',
);

has 'conn' => (
  is      => 'ro',
  isa     => InstanceOf['Net::LDAP'],
  lazy    => 1,
  builder => '_build_conn',
  clearer => 'clear_conn',
);

sub _build__file {
  return dist_file('Net-LDAP-Simple', 'ldap.conf');
}

sub _build__conf($self) {
  do $self->_file;
}

sub _build_user_basedn($self) {
  return $self->_conf->{user_basedn};
}

sub _build_user_scope($self) {
  return $self->_conf->{user_scope};
}

sub _build_role_scope($self) {
  return $self->_conf->{role_scope};
}

sub _build_role_field($self) {
  return $self->_conf->{role_field};
}

sub _build_conn($self) {
  return $self->_bind(
    binddn => $self->binddn,
    bindpw => $self->bindpw,
  );
}

sub _build__role_map($self) {
  return {map {$_ => $self->_roles->{$_}->[-1]} keys $self->_roles->%*};
}

sub _is_conn_reset ($self, %params) {
  if ($params{error} =~ $CONN_RESET_REGEXP) {
    carp "detected connection reset error ($params{error})";
    return $TRUE;
  }

  return $FALSE;
}

sub _is_auth_failure ($self, %params) {
  if ($params{error} =~ $AUTH_FAIL_REGEXP) {
    carp "detected security context error code ($params{error})";
    return $TRUE;
  }

  return $FALSE;
}

sub _user_filter ($self, $username) {
  return sprintf $self->_conf->{user_filter}, $username;
}

sub _role_filter ($self, $cn) {
  return sprintf $self->_conf->{role_filter}, $cn;
}

sub _role_search_ou ($self, $role) {
  return unless $self->has_role($role);

  my @role_search_path = reverse @{$self->_roles->{$role}};
  my $search_ou        = 'CN=' . shift @role_search_path;

  if (@role_search_path) {
    $search_ou .= $COMMA . join($COMMA, map {"OU=$_"} @role_search_path);    # TODO - clean this up
  }

  return $search_ou;
}

sub _role_basedn ($self, $role) {
  return join($COMMA, ($self->_role_search_ou($role), $self->_conf->{role_basedn}));
}

sub _role_ou ($self, $role) {
  return $self->_role_map->{$role};
}

sub _bind ($self, %params) {
  my $conn     = Net::LDAP->new($self->host);
  my $attempts = 0;

BIND: {
    my ($msg, $is_error);

    try {
      $msg      = $conn->bind($params{binddn}, password => $params{bindpw});
      $is_error = $msg->is_error;
      $msg      = $msg->error;
    } catch {
      $msg      = $EVAL_ERROR;
      $is_error = $TRUE;
    }

    if ($is_error) {
      unless ($self->_is_auth_failure(error => $msg)) {
        redo BIND if $attempts++ < $MAX_AUTH_ATTEMPTS;
      }

      Net::LDAP::Simple::Exceptions::FailedBind->throw(error => $msg);
    }
  }

  return $conn;
}

=method has_role($role)

Has the role been defined. Returns true or false.

@PARAMS: $role

=cut
sub has_role($self, $role) {
  return exists $self->_roles->{$role};
}

=method add_role(%params)

Added a new role to the object. 

@PARAMS: %params

  (
    role => listref,
  )

=cut
sub add_role($self, $role, $groups) {
  push $self->_roles->{$role}->@*, $groups->@*;
}

=method search(%params)

Wrapper for the Net::LDAP search method that will catch "connection reset" conditions
and reconnect to the LDAP host. This usually happens with long lived ldap sessions.

Returns the Net::LDAP search object.

@PARAMS: %params
  (
    base   => string,
    filter => string,
    scope  => string,
    attrs  => string,
  )

=cut
sub search ($self, %params) {
SEARCH: {
    my $search = $self->conn->search(%params);

    if ($search->is_error) {
      if ($self->_is_conn_reset(error => $search->error)) {
        $self->clear_conn;
        redo SEARCH;
      }

      Net::LDAP::Simple::Exceptions::FailedSearch->throw(error => $search->error);
    }

    return $search;
  }
  return;
}

=method unbind()

Wrapper for Net::LDAP::unbind() to disconnect the ldap session.

=cut
sub unbind($self) {
  return $self->conn->unbind;
}

=method lookup_user(%params)

Given a username, sAMAccountName, determine if the user exists in Active Directory.
Returns false, 0, if the user does not exist, otherwsie returns the Net::LDAP::Entry
object for the user search.

@PARAMS: %params
  (
    user => string,
  )
=cut
sub lookup_user ($self, %params) {
  return $FALSE unless $params{user};

  my $search = $self->search(
    base   => $self->user_basedn,
    scope  => $self->user_scope,
    filter => $self->_user_filter($params{user}),
  );

  return $FALSE unless $search->entries;
  return $search->pop_entry;
}

=method check(%params)

Determine if the given user credentials are valid by attempting to bind to LDAP
as the user. Returns true, 1, if successfully able to bind as the user and false, 0,
if not.

Detects and recovers from "connection reset errors" from Active Directory when persistent ldap
connections are timed out and the connection is reset.

@PARAMS: %params
  (
    user => string,
    pass => string,
  )
=cut
sub check ($self, %params) {
  return $FALSE unless exists $params{user} or $params{pass};

  my $user_entry = $self->lookup_user(%params);
  return $FALSE unless $user_entry;

  try {
    $self->_bind(
      binddn => $user_entry->dn,
      bindpw => $params{pass},
    );
  } catch {
    return $FALSE;
  }

  return $TRUE;
}

=method is_role(%args)

This method is used to determine if a given user is a member of a given role.
Returns true or false (1 or 0).

@PARAMS: %args
  (
    user => string,
    role => string,
  )

=cut
sub is_role ($self, %params) {
  return $FALSE unless $params{user} and $params{role};
  return $FALSE unless $self->has_role($params{role});

  my $user_entry = $self->lookup_user(%params);
  return $FALSE unless $user_entry;

  my $search = $self->search(
    base   => $self->_role_basedn($params{role}),
    filter => $self->_role_filter($user_entry->get_value('cn')),
    scope  => $self->role_scope,
    attrs  => [$self->role_field],
  );

  return $FALSE unless $search->count;

  my %user_roles = map {$_->get_value($self->role_field) => 1} $search->entries;

  return $TRUE if exists $user_roles{$self->_role_ou($params{role})};
  return $FALSE;
}

=method get_user(%args)

This method returns a Net::LDAP::Simple::User object for the given username.
Return undef on lookup failure.

@PARAMS: %args
  (
    user => string,
  )
=cut
sub get_user ($self, %params) {
  return unless $params{user};
  my $entry = $self->lookup_user(%params);
  return Net::LDAP::Simple::User->new(ldap_entry => $entry);
}

1;
