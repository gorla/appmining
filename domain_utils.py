# util function to cluster domains

#  https://github.com/ztane/python-Levenshtein/wiki#Levenshtein-distance
import Levenshtein
import numpy as np
import os
import re
import scipy.cluster.hierarchy


class DomainParser():
    black_list = ["javax.xml.XMLConstants"]
    third_level_domains = ["google", "amazon", "facebook", "flipboard",
                           "windows", "twitter", "yahoo", "3g", "appnav",
                           "aol", "baidu", "booking", "cmcm", "flipboard",
                           "goforandroid", "instagram", "kik", "linkedin",
                           "mozilla", "naver", "paypal", "pinterest", "qq",
                           "skype", "tripadvisor", "uber"]

    suffix_list = None

    def __init__(self):
        self.no_tuple = False

        # load the suffix list into python
        __location__ = os.path.realpath(
            os.path.join(os.getcwd(), os.path.dirname(__file__)))
        with open(os.path.join(__location__,
                               'public_suffix_list.txt')) as f:
            self.suffix_list = f.read().splitlines()
            # self.suffix_list = [s.decode('utf-8') for s in self.suffix_list ]
            self.suffix_list = ['.' + s for s in self.suffix_list]
            self.suffix_list.sort(key=len, reverse=True)

    def lev_dist(self, w1, w2):
        w1 = self.strip_num(w1)
        w2 = self.strip_num(w2)
        return Levenshtein.distance(w1, w2)

    def is_domain(self, line):
        return bool(re.search("\w\.\w", line))

    def is_ip(self, line):
        return bool(re.search("^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", line))

    def strip_num(self, line):
        return re.sub("[0-9]", "", line) if not self.is_ip(line) else line

    def del_hex(self, line):
        return '' if self.check_hex(line) else line

    def is_blacklisted(self, line):
        return line in self.black_list

    def check_hex(self, line, min_len=5):
        if line.isalpha() | len(line) < min_len:
            return False
        try:
            int(line, 16)
        except ValueError:
            return False
        return True

    def trim_hex(self, domain):
        prefix = domain.split('.')[0]
        suffix = '.'.join(domain.split('.')[1:])
        parts = re.split('[_/-]', prefix)
        parts = [self.del_hex(p) for p in parts]
        res = '-'.join(filter(None, parts))
        return '.'.join(filter(None, [res, suffix]))

    def get_domain(self, url):
        url = re.sub("^http[s]?://", '', url)
        return re.sub("([^/\?]+)[/\?]?.*", r"\1", url)

    def del_noise(self, domains):
        domains = [(re.sub("{[0-9a-zA-Z]*}", "", d[0]), d[1]) for d in domains]  # remove {s}
        domains = [(re.sub("[\*\(\)]", "", d[0]), d[1]) for d in domains]  # remove * (asterisk)
        domains = [(re.sub("%[a-z]", "", d[0]), d[1]) for d in domains]  # delete http://%s-%d cases
        domains = list(map(lambda x: ("" if '@' in d[0] else x[0], x[1]), domains))  # remove emails
        domains = list(map(lambda x: (x[0] if self.is_domain(x[0]) else "", x[1]), domains))
        domains = list(map(lambda x: (self.trim_hex(x[0]), x[1]), domains))
        domains = list(map(lambda x: (x[0] if not self.is_blacklisted(x[0]) else "", x[1]), domains))
        return domains

    def strip_domain(self, domains):
        no_www = [re.sub("^(www)?\.?", "", d) for d in domains]
        no_path = [re.sub("\?.*", "", d) for d in no_www]
        no_port = [re.sub(":[0-9]*", "", d) for d in no_path]

        res = no_port
        return res

    # cleans an url and returns the domain
    def clean_domain(self, domain):
        domain = self.get_domain(domain)
        domain = re.sub("{[0-9a-zA-Z]*}", "", domain)  # remove {s}
        domain = re.sub("[\*\(\)]", "", domain)  # remove * (asterisk)
        domain = re.sub("%[a-z]", "", domain)  # delete http://%s-%d cases
        # if there are consecutive dots, just keep the latest substring: in
        # this case something inside the url was removed
        if '..' in domain:
            domain = domain.split('..')[-1]
        if '@' in domain:  # skip emails
            return ''
        if not self.is_domain(domain):  # check format word.word
            return ''
        if self.is_blacklisted(domain):  # skip blacklisted
            return ''
        domain = self.trim_hex(domain)  # removes hex strings

        domain = re.sub("^(www)?\.?", "", domain)  # removes www
        domain = re.sub("\?.*", "", domain)  # removes path
        domain = re.sub(":[0-9]*", "", domain)  # removes port

        if domain.endswith('.'):  # remove trailing dot
            domain = domain[:-1]
        if domain.startswith('.'):  # remove starting dot
            domain = domain[1:]

        return domain

    def get_average(self, cluster):
        # value = Levenshtein.median(cluster)
        cluster = map(lambda c: ":".join(filter(None, [c[0], c[1]])), cluster)
        value = min(cluster, key=len)
        return value

    def cluster_domains(self, domains, max_dist=2, ):
        """
        adapted from https://github.com/smilli/clust/tree/master/clust
        Params:
            domains: [list of tuples] List of tuples (domain, lib) to cluster.
            max_dist: [float] Maximum distance allowed for two clusters to merge.
            method: [string] Method to use for clustering.  'single',
                'complete', 'average', 'centroid', 'median', 'ward', or 'weighted'.
                See http://docs.scipy.org/doc/scipy/reference/generated/scipy.cluster.hierarchy.linkage.html for details.
        Returns:
            clusters: [list] List of ngrams in each cluster.
        """

        # lists preserve the order
        # stub for compatibility
        if len(domains) == 0:
            return {}
        if not isinstance(next(iter(domains)), tuple):
            domains = list(map(lambda x: (x, ""), domains))
            self.no_tuple = True

        urls = list(map(lambda x: x[0], domains))

        # process urls and make them into domains_clean
        for i in range(0, len(urls)):
            # print url list before modifications
            # print urls[i]

            # remove suffix if found in suffix list
            for s in self.suffix_list:
                if urls[i].endswith(s):
                    urls[i] = urls[i][:-(len(s))]
                    break

            # get second level domain, or second and third level
            # if the element is in the white list
            split = urls[i].split('.')
            second_level_domain = split[-1]

            # we only get the third level domain if it is in the string
            if second_level_domain in self.third_level_domains and \
                    len(split) > 1:
                urls[i] = '.'.join((split[-2], second_level_domain))
            else:
                urls[i] = second_level_domain

            # print url list after modifications
            # print urls[i]
            # print '-'

        libs = list(map(lambda x: x[1], domains))
        domains_clean = list(map(lambda u, l: ":".join(filter(None, [u, l])), urls, libs))

        if len(domains_clean) > 1:
            indices = np.triu_indices(len(domains), 1)
            pairwise_dists = np.apply_along_axis(
                lambda col: self.lev_dist(domains_clean[col[0]],
                                          domains_clean[col[1]]),
                0, indices)
            hierarchy = scipy.cluster.hierarchy.linkage(pairwise_dists, method='ward')
            clusters = dict((i, [i]) for i in range(len(domains)))
            for (i, iteration) in enumerate(hierarchy):
                cl1, cl2, dist, num_items = iteration
                if dist > max_dist:
                    break
                items1 = clusters[cl1]
                items2 = clusters[cl2]
                del clusters[cl1]
                del clusters[cl2]
                clusters[len(domains) + i] = items1 + items2
        else:
            clusters = {0: [0]}

        domain_clusters = {}
        for cluster in clusters.values():
            avg_value = self.get_average([domains[i] for i in cluster])
            for d in cluster:
                domain_clusters[domains[d]] = avg_value
        res = {}
        for domain in domains:
            res[self.unwrap(domain)] = domain_clusters[domain]

        return res

    def unwrap(self, d):
        return d[0] if self.no_tuple else d


if __name__ == "__main__":
    data = [("9.google.com", 'com/google/q'), ("*.google.com", "wewe/q"), ("google.com", 'com/google/q'),
            ("facebook.com", "com/face/"), ("https://graph.%s", "'com/face/")]
    dd = DomainParser()
    print(dd.cluster_domains(data))
    data1 = ["9.google.com", "i.google.com", "google.com", "facebook.com", "https://graph.%s"]
    d1 = DomainParser()
    print(d1.cluster_domains(data1))
