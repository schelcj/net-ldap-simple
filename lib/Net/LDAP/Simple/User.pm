package Net::LDAP::Simple::User;

# ABSTRACT: This modules provides a simple wrapper for a Net::LDAP::Entry object to retrieve info such as first and last names.

=head1 SYNOPSIS

    my $ldap = Net::LDAP::Simple->new();

    my $user = Net::LDAP::Simple::User->new(ldap_entry => $ldap->lookup_user('foo'));

    my $firstname = $user->firstname;

=cut

use Modern::Perl '2015';
use Moose;

use experimental qw(signatures);

=method new(%params)

Instantiate a new Net::LDAP::Simple::User object.

    @PARAMS: %params
        (
            ldap_entry => object
        )

=over 2

=item B<ldap_entry>

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

has ldap_entry => (
  is       => 'ro',
  isa      => 'Net::LDAP::Entry',
  required => 1,
);

has firstname => (
  is      => 'ro',
  isa     => 'Str',
  lazy    => 1,
  builder => '_build_firstname',
);

has lastname => (
  is      => 'ro',
  isa     => 'Str',
  lazy    => 1,
  builder => '_build_lastname',
);

has email => (
  is      => 'ro',
  isa     => 'Str',
  lazy    => 1,
  builder => '_build_email',
);

has username => (
  is      => 'ro',
  isa     => 'Str',
  lazy    => 1,
  builder => '_build_username'
);

sub _build_firstname($self) {
  return $self->ldap_entry->get_value('givenName');
}

sub _build_lastname($self) {
  return $self->ldap_entry->get_value('sn');
}

sub _build_email($self) {
  return $self->ldap_entry->get_value('mail');
}

sub _build_username($self) {
  return $self->ldap_entry->get_value('sAMAccountName');
}

no Moose;
__PACKAGE__->meta->make_immutable;

1;
