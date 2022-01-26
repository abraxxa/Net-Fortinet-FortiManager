package Net::Fortinet::FortiManager;

# ABSTRACT: Fortinet FortiManager REST API client library

use 5.024;
use Moo;
use feature 'signatures';
use Types::Standard qw( ArrayRef HashRef InstanceOf Str );
use Types::Common::Numeric qw( PositiveInt );
use Carp qw( croak );
use List::Util qw( all );
use JSON::RPC::Common::Marshal::HTTP;

no warnings "experimental::signatures";

=head1 SYNOPSIS

    use strict;
    use warnings;
    use Net::Fortinet::FortiManager;

    my $fortimanager = Net::Fortinet::FortiManager->new(
        server      => 'https://fortimanager.example.com',
        user        => 'username',
        passwd      => '$password',
        clientattrs => {
            timeout     => 10,
        },
    );

    $fortimanager->login;

    $fortimanager->adom('adomname');

=head1 DESCRIPTION

This module is a client library for the Fortigate FortiManager JSONRPC-like
API.
Currently it is developed and tested against version 6.4.6.

=for Pod::Coverage has_user has_passwd has_api_key

=cut

has 'user' => (
    isa => Str,
    is  => 'rw',
    predicate => 1,
);

has 'passwd' => (
    isa => Str,
    is  => 'rw',
    predicate => 1,
);

has '_sessionid' => (
    isa         => Str,
    is          => 'rw',
    predicate   => 1,
    clearer     => 1,
);

has '_last_transaction_id' => (
    isa         => PositiveInt,
    is          => 'rw',
    predicate   => 1,
    clearer     => 1,
);

sub _get_transaction_id ($self) {
    my $id;
    if ($self->_has_last_transaction_id) {
        $id = $self->_last_transaction_id;
        $id++;
    }
    else {
        $id = 1;
    }

    $self->_last_transaction_id($id);
    return $id;
}

has '_jsonrpc_marshal_http' => (
    isa     => InstanceOf['JSON::RPC::Common::Marshal::HTTP'],
    is      => 'ro',
    default => sub { JSON::RPC::Common::Marshal::HTTP->new },
);

=attr adoms

Returns a list of hashrefs containing name and uuid of all ADOMs which gets
populated by L</login>.

=cut

has 'adoms' => (
    is  => 'rwp',
    isa => ArrayRef[Str],
);

=attr adom

The name of the ADOM which is used by all methods.
Defaults to 'root'.

=cut

has 'adom' => (
    is      => 'rw',
    isa     => Str,
    default => sub { 'root' },
);

with 'Role::REST::Client';

# around 'do_request' => sub($orig, $self, $method, $uri, $opts) {
#     warn 'request: ' . np($method, $uri, $opts);
#     my $response = $orig->($self, $method, $uri, $opts);
#     warn 'response: ' .  np($response);
#     return $response;
# };

sub _exec_method ($self, $method, $params = undef) {
    croak 'params needs to be an arrayref'
        if defined $params && ref $params ne 'ARRAY';

    my $body = {
        id      => $self->_get_transaction_id,
        method  => $method,
        params  => $params,
    };
    $body->{session} = $self->_sessionid
        if $self->_has_sessionid;

    # p $body;
    my $res = $self->post('/jsonrpc', $body);
    # p $res;

    my $result = $self->_jsonrpc_marshal_http
        ->response_to_result($res->response);
    croak $result
        if $result->has_error;

    return $result;
}

=method exec_method

Executes a method with the specified parameters.

Returns its response.

This is the lowest level method which can be used to execute every API action
that's available.
It does the http and JSONRPC error handling and extraction of the result
from the JSONRPC response.

=cut

sub exec_method ($self, $method, $url, $params = undef) {
    croak 'params needs to be a hashref'
        if defined $params && ref $params ne 'HASH';

    my %full_params = defined $params
        ? $params->%*
        : ();
    $full_params{url} = $url;
    my $rv = $self->_exec_method($method, [\%full_params])->result;

    # the existance of {result}[0] is already verified by _rpc_error_handler
    # called in _exec_method
    if (exists $rv->{result}[0]->{data}) {
        return $rv->{result}[0]->{data};
    }
    return 1;
}

=method login

Logs into the Fortinet FortiManager.

=cut

sub login ($self) {
    die "user and password required\n"
        unless $self->has_user && $self->has_passwd;

    my $res = $self->_exec_method('exec', [{
        url => "/sys/login/user",
        data => {
            user   => $self->user,
            passwd => $self->passwd,
        },
    }]);

    $self->_sessionid($res->result->{session});

    $self->_set_adoms($self->list_adoms);

    return 1;
}

=method logout

Logs out of the Fortinet FortiManager.

=cut

sub logout ($self) {
    $self->exec_method('exec', '/sys/logout');
    $self->_clear_sessionid;
    $self->_clear_last_transaction_id;

    return 1;
}

=method get_sys_status

Returns /sys/status.

=cut

sub get_sys_status ($self) {
    return $self->exec_method('get', '/sys/status');
}

=method list_adoms

Returns an arrayref of ADOMs by name.

=cut

sub list_adoms ($self) {
    my @adoms = map {
        $_->{name}
    } $self->exec_method('get', '/dvmdb/adom', {
        fields  => [qw( name )],
    })->@*;
    return \@adoms;
}

=method list_firewall_addresses

Returns an arrayref of firewall addresses.

=cut

sub list_firewall_addresses ($self, $params = {}) {
    $self->exec_method('get', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/address', $params);
}

=method get_firewall_address

Takes a firewall address name and an optional parameter hashref.

Returns its data as a hashref.

=cut

sub get_firewall_address ($self, $name, $params = {}) {
    $self->exec_method('get', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/address/'. $name, $params);
}

=method create_firewall_address

Takes a firewall address name and a hashref of address config.

Returns true on success.

Throws an exception on error.

=cut

sub create_firewall_address ($self, $name, $data) {
    my $params = {
        data => [{
            $data->%*,
            name => $name,
        }],
    };
    $self->exec_method('set', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/address', $params);
}

=method update_firewall_address

Takes a firewall address name and a hashref of address config.

Returns true on success.

Throws an exception on error.

=cut

sub update_firewall_address ($self, $name, $data) {
    my $params = {
        data => {
            $data->%*,
        },
    };
    $self->exec_method('update', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/address/' . $name, $params);
}

=method delete_firewall_address

Takes a firewall address name.

Returns true on success.

Throws an exception on error.

=cut

sub delete_firewall_address ($self, $name) {
    $self->exec_method('delete', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/address/' . $name);
}

=method list_firewall_address_groups

Returns an arrayref of firewall address groups.

=cut

sub list_firewall_address_groups ($self, $params = {}) {
    $self->exec_method('get', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/addrgrp', $params);
}

=method get_firewall_address_group

Takes a firewall address group name and an optional parameter hashref.

Returns its data as a hashref.

=cut

sub get_firewall_address_group ($self, $name, $params = {}) {
    $self->exec_method('get', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/addrgrp/'. $name, $params);
}

=method create_firewall_address_group

Takes a firewall address group name and a hashref of address group config.

Returns true on success.

Throws an exception on error.

=cut

sub create_firewall_address_group ($self, $name, $data) {
    my $params = {
        data => [{
            $data->%*,
            name => $name,
        }],
    };
    $self->exec_method('set', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/addrgrp', $params);
}

=method update_firewall_address_group

Takes a firewall address group name and a hashref of address group config.

Returns true on success.

Throws an exception on error.

=cut

sub update_firewall_address_group ($self, $name, $data) {
    my $params = {
        data => {
            $data->%*,
        },
    };
    $self->exec_method('update', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/addrgrp/' . $name, $params);
}

=method delete_firewall_address_group

Takes a firewall address group name.

Returns true on success.

Throws an exception on error.

=cut

sub delete_firewall_address_group ($self, $name) {
    $self->exec_method('delete', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/addrgrp/' . $name);
}

=method list_firewall_ipv6_addresses

Returns an arrayref of firewall IPv6 addresses.

=cut

sub list_firewall_ipv6_addresses ($self, $params = {}) {
    $self->exec_method('get', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/address6', $params);
}

=method get_firewall_ipv6_address

Takes a firewall IPv6 address name and an optional parameter hashref.

Returns its data as a hashref.

=cut

sub get_firewall_ipv6_address ($self, $name, $params = {}) {
    $self->exec_method('get', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/address6/'. $name, $params);
}

=method create_firewall_ipv6_address

Takes a firewall IPv6 address name and a hashref of address config.

Returns true on success.

Throws an exception on error.

=cut

sub create_firewall_ipv6_address ($self, $name, $data) {
    my $params = {
        data => [{
            $data->%*,
            name => $name,
        }],
    };
    $self->exec_method('set', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/address6', $params);
}

=method update_firewall_ipv6_address

Takes a firewall IPv6 address name and a hashref of address config.

Returns true on success.

Throws an exception on error.

=cut

sub update_firewall_ipv6_address ($self, $name, $data) {
    my $params = {
        data => {
            $data->%*,
        },
    };
    $self->exec_method('update', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/address6/' . $name, $params);
}

=method delete_firewall_ipv6_address

Takes a firewall IPv6 address name.

Returns true on success.

Throws an exception on error.

=cut

sub delete_firewall_ipv6_address ($self, $name) {
    $self->exec_method('delete', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/address6/' . $name);
}

=method list_firewall_ipv6_address_groups

Returns an arrayref of firewall IPv6 address groups.

=cut

sub list_firewall_ipv6_address_groups ($self, $params = {}) {
    $self->exec_method('get', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/addrgrp6', $params);
}

=method get_firewall_ipv6_address_group

Takes a firewall IPv6 address group name and an optional parameter hashref.

Returns its data as a hashref.

=cut

sub get_firewall_ipv6_address_group ($self, $name, $params = {}) {
    $self->exec_method('get', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/addrgrp6/'. $name, $params);
}

=method create_firewall_ipv6_address_group

Takes a firewall IPv6 address group name and a hashref of address group config.

Returns true on success.

Throws an exception on error.

=cut

sub create_firewall_ipv6_address_group ($self, $name, $data) {
    my $params = {
        data => [{
            $data->%*,
            name => $name,
        }],
    };
    $self->exec_method('set', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/addrgrp6', $params);
}

=method update_firewall_ipv6_address_group

Takes a firewall IPv6 address group name and a hashref of address group config.

Returns true on success.

Throws an exception on error.

=cut

sub update_firewall_ipv6_address_group ($self, $name, $data) {
    my $params = {
        data => {
            $data->%*,
        },
    };
    $self->exec_method('update', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/addrgrp6/' . $name, $params);
}

=method delete_firewall_ipv6_address_group

Takes a firewall IPv6 address group name.

Returns true on success.

Throws an exception on error.

=cut

sub delete_firewall_ipv6_address_group ($self, $name) {
    $self->exec_method('delete', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/addrgrp6/' . $name);
}

=method list_firewall_services

Returns an arrayref of firewall services.

=cut

sub list_firewall_services ($self, $params = {}) {
    $self->exec_method('get', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/service/custom', $params);
}

=method get_firewall_service

Takes a firewall service name and an optional parameter hashref.

Returns its data as a hashref.

=cut

sub get_firewall_service ($self, $name, $params = {}) {
    $self->exec_method('get', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/service/custom/'. $name, $params);
}

=method create_firewall_service

Takes a firewall service name and a hashref of service config.

Returns true on success.

Throws an exception on error.

=cut

sub create_firewall_service ($self, $name, $data) {
    my $params = {
        data => [{
            $data->%*,
            name => $name,
        }],
    };
    $self->exec_method('set', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/service/custom', $params);
}

=method update_firewall_service

Takes a firewall service name and a hashref of service config.

Returns true on success.

Throws an exception on error.

=cut

sub update_firewall_service ($self, $name, $data) {
    my $params = {
        data => {
            $data->%*,
        },
    };
    $self->exec_method('update', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/service/custom/' . $name, $params);
}

=method delete_firewall_service

Takes a firewall service name.

Returns true on success.

Throws an exception on error.

=cut

sub delete_firewall_service ($self, $name) {
    $self->exec_method('delete', '/pm/config/adom/' . $self->adom .
        '/obj/firewall/service/custom/' . $name);
}

1;
