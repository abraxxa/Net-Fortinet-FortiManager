use Test2::V0;
use Test2::Tools::Compare qw( array bag hash all_items all_values );
use Test2::Tools::Subtest qw( subtest_buffered );
use Net::Fortinet::FortiManager;

use DDP;

skip_all "environment variables not set"
    unless (exists $ENV{NET_FORTINET_FORTIMANAGER_HOSTNAME}
        && exists $ENV{NET_FORTINET_FORTIMANAGER_USERNAME}
        && exists $ENV{NET_FORTINET_FORTIMANAGER_PASSWORD}
        && exists $ENV{NET_FORTINET_FORTIMANAGER_POLICY});

like (
    dies {
        my $fortimanager = Net::Fortinet::FortiManager->new(
            server      => 'https://' . $ENV{NET_FORTINET_FORTIMANAGER_HOSTNAME},
            user        => 'foo',
            passwd      => 'bar',
            clientattrs => {
                insecure => 1,
            },
        );
        $fortimanager->login;
    },
    qr/^jsonrpc error \(-11\): /,
    'login with incorrect credentials throws exception'
);

my $fortimanager = Net::Fortinet::FortiManager->new(
    server      => 'https://' . $ENV{NET_FORTINET_FORTIMANAGER_HOSTNAME},
    user        => $ENV{NET_FORTINET_FORTIMANAGER_USERNAME},
    passwd      => $ENV{NET_FORTINET_FORTIMANAGER_PASSWORD},
    clientattrs => {
        insecure => 1,
    },
);

ok(!$fortimanager->_has_last_transaction_id,
    'no transaction id after construction');

ok(!$fortimanager->adoms, 'no adoms after construction');

is($fortimanager->adom, 'root', "adom set to 'root' after construction");

ok($fortimanager->login, 'login to Fortinet FortiManager successful');

ok($fortimanager->_has_last_transaction_id,
    'transaction id set after login');

ok($fortimanager->_sessionid, 'sessionid set after successful login');

is($fortimanager->adoms, bag {
    all_items D();
}, 'adoms returns arrayref of ADOM names');

END {
    diag('logging out');
    $fortimanager->logout
        if defined $fortimanager;
}

like (
    dies {
        $fortimanager->exec_method('get', '/does/not/exist');
    },
    qr/^http error \(503\): /,
    'calling exec_method with a nonexisting url throws correct exception'
);

is($fortimanager->exec_method('get',
    '/pm/config/adom/root/obj/firewall/address'),
    bag {
        all_items hash {
            etc();
        };
    }, 'exec_method without parameters response ok');

is($fortimanager->exec_method('get',
    '/pm/config/adom/root/obj/firewall/address',
    {
        fields => [qw( name type )],
    }),
    bag {
        all_items hash {
            field 'name' => D();
            field 'type' => D();

            etc();
        };
    }, 'exec_method with parameters response ok');

is($fortimanager->get_sys_status, hash {
    field 'Hostname'    => D();
    field 'Version'     => D();

    etc();
}, 'sys_status response ok');

is($fortimanager->list_adoms, bag {
    all_items D();
}, 'list_adoms returns arrayref of ADOM names');

subtest_buffered 'addresses' => sub {
    is($fortimanager->list_firewall_addresses,
        bag {
            all_items hash {
                field 'name'    => D();
                field 'type'    => D();

                etc();
            };

            end();
        },
        'list_firewall_addresses ok');

    ok($fortimanager->create_firewall_address('host_test1', {
        subnet => '192.0.2.10/255.255.255.255',
    }), 'create_firewall_address for host ok');

    ok($fortimanager->create_firewall_address('net_test1', {
        subnet => '192.0.2.10/255.255.255.0',
    }), 'create_firewall_address for network ok');

    ok($fortimanager->create_firewall_address('range_test1', {
        'start-ip'  => '192.0.2.10',
        'end-ip'    => '192.0.2.20',
        type        => 'iprange',
    }), 'create_firewall_address for range ok');

    ok($fortimanager->create_firewall_address('fqdn_acme.example.net', {
        fqdn    => 'acme.example.net',
        type    => 'fqdn',
    }), 'create_firewall_address for FQDN ok');

    is($fortimanager->get_firewall_address('fqdn_acme.example.net'),
        hash {
            field 'fqdn'    => 'acme.example.net';
            field 'type'    => 2;

            etc();
        }, 'get_firewall_address for FQDN ok');

    ok($fortimanager->update_firewall_address('range_test1', {
        'end-ip'    => '192.0.2.30',
    }), 'update_firewall_address for range ok');

    ok($fortimanager->delete_firewall_address('range_test1'),
        'delete_firewall_address ok');
};

subtest_buffered 'IPv6 addresses' => sub {
    is($fortimanager->list_firewall_ipv6_addresses,
        bag {
            all_items hash {
                field 'name'    => D();
                field 'type'    => D();

                etc();
            };

            end();
        },
        'list_firewall_ipv6_addresses ok');

    ok($fortimanager->create_firewall_ipv6_address('host_v6_test1', {
        ip6 => '2001:db8::a/128',
    }), 'create_firewall_ipv6_address for host ok');

    ok($fortimanager->create_firewall_ipv6_address('net_v6_test1', {
        ip6 => '2001:db8::0/64',
    }), 'create_firewall_ipv6_address for network ok');

    ok($fortimanager->create_firewall_ipv6_address('range_v6_test1', {
        'start-ip'  => '2001:db8::a',
        'end-ip'    => '2001:db8::14',
        type        => 'iprange',
    }), 'create_firewall_ipv6_address for range ok');

    ok($fortimanager->create_firewall_ipv6_address('fqdn_v6_acme.example.net', {
        fqdn    => 'acme.example.net',
        type    => 'fqdn',
    }), 'create_firewall_ipv6_address for FQDN ok');

    is($fortimanager->get_firewall_ipv6_address('fqdn_v6_acme.example.net'),
        hash {
            field 'fqdn'    => 'acme.example.net';
            field 'type'    => 4;

            etc();
        }, 'get_firewall_ipv6_address for FQDN ok');

    ok($fortimanager->update_firewall_ipv6_address('range_v6_test1', {
        'end-ip'    => '2001:db8::1d',
    }), 'update_firewall_ipv6_address for range ok');

    ok($fortimanager->delete_firewall_ipv6_address('range_v6_test1'),
        'delete_firewall_ipv6_address ok');
};

subtest_buffered 'services' => sub {
    is($fortimanager->list_firewall_services,
        bag {
            all_items hash {
                field 'name'        => D();
                field 'protocol'    => D();

                etc();
            };

            end();
        },
        'list_firewall_services ok');

    ok($fortimanager->create_firewall_service('test_tcp_1234', {
        protocol        => 'TCP/UDP/SCTP',
        'tcp-portrange' => '1234'
    }), 'create_firewall_service for TCP service ok');

    ok($fortimanager->create_firewall_service('test_udp_1234', {
        protocol        => 'TCP/UDP/SCTP',
        'udp-portrange' => '1234'
    }), 'create_firewall_service for UDP service ok');

    ok($fortimanager->create_firewall_service('test_icmp_echo', {
        protocol        => 'ICMP',
        icmptype        => '8'
    }), 'create_firewall_service for ICMP service ok');

    is($fortimanager->get_firewall_service('test_tcp_1234'),
        hash {
            field 'protocol'        => 5;
            field 'tcp-portrange'   => array {
                item '1234';

                end();
            };

            etc();
        }, 'get_firewall_service for TCP service ok');

    ok($fortimanager->update_firewall_service('test_tcp_1234', {
        'tcp-portrange' => '12345'
    }), 'update_firewall_service for TCP service ok');

    ok($fortimanager->delete_firewall_service('test_tcp_1234'),
        'delete_firewall_service ok');
};

done_testing();
