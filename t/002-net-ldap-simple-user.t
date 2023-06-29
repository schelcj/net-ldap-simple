#!/usr/bin/env perl

use FindBin;
BEGIN {
  unshift @INC, "$FindBin::Bin/tests";
  unshift @INC, "$FindBin::Bin/../lib";
}

use Test::Net::LDAP::Simple::User;
Test::Class->runtests;
