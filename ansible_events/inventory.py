
def parse_inventory_pattern(pattern):
    return [i.strip() for i in pattern.split(',')]


def matches_host(subpattern, host):
    if subpattern == host:
        print('matches_host', subpattern, host, True)
        return True
    print('matches_host', subpattern, host, False)
    return False


def matching_hosts(inventory, pattern):
    print('matching_hosts', inventory, pattern)
    subpatterns = parse_inventory_pattern(pattern)
    hosts = []
    for groupname, group in inventory.items():
        for host in group.get('hosts').keys():
            for sp in subpatterns:
                if matches_host(sp, host):
                    hosts.append(host)
                    break
    return hosts
