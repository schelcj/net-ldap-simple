package Net::LDAP::Simple::Exceptions;

# ABSTRACT: LDAP specific exceptions

use Exception::Class (
  __PACKAGE__ . '::FailedBind' => {
    description => 'Failed to bind',
  },
  __PACKAGE__ . '::FailedSearch' => {
    description => 'Failed to search',
  },
);

1;
