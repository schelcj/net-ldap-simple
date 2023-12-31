package Net::LDAP::Simple::User;

# ABSTRACT: This modules provides a simple wrapper for a Net::LDAP::Entry object to retrieve info such as first and last names.

=head1 SYNOPSIS

    my $ldap = Net::LDAP::Simple->new();

    my $user = Net::LDAP::Simple::User->new(ldap_entry => $ldap->lookup_user('foo'));

    my $firstname = $user->firstname;

=cut

use Moo;
use Types::Standard qw(Str InstanceOf);
use namespace::autoclean;

use Modern::Perl '2015';
use experimental qw(signatures);
no warnings qw(experimental::signatures);

=method new(%params)

Instantiate a new Net::LDAP::Simple::User object.

    @PARAMS: %params
        (
            ldap_entry => object
        )

=over 2

=item B<entry>

    An existing Net::LDAP::Entry object.
    Required

=item firstname()

Returns the value of the 'givenName` field.

=item lastname()

Returns the value of the 'sn` field.

=item email()

Returns the value of the `mail` field.

=item username()

Returns the value of the `sAMAccountName` field.

=back

=cut

has entry => (
  is       => 'ro',
  isa      => InstanceOf['Net::LDAP::Entry'],
  required => 1,
);

has firstname => (
  is      => 'ro',
  isa     => Str,
  lazy    => 1,
  builder => '_build_firstname',
);

has lastname => (
  is      => 'ro',
  isa     => Str,
  lazy    => 1,
  builder => '_build_lastname',
);

has email => (
  is      => 'ro',
  isa     => Str,
  lazy    => 1,
  builder => '_build_email',
);

has username => (
  is      => 'ro',
  isa     => Str,
  lazy    => 1,
  builder => '_build_username'
);

sub _build_firstname($self) {
  return $self->entry->get_value('givenName');
}

sub _build_lastname($self) {
  return $self->entry->get_value('sn');
}

sub _build_email($self) {
  return $self->entry->get_value('mail');
}

sub _build_username($self) {
  return $self->entry->get_value('sAMAccountName');
}

1;
