import os
import xmltodict
import re

src_dir = './permissions'
dest_file = 'droid_perm_mapping.txt'
pmapping = []
fc = 0
for root, dirs, files in os.walk(src_dir):
    for fname in files:
        if fname.endswith('.xml'):
            with open(os.path.join(root, fname)) as fd:
                perm_xml = xmltodict.parse(fd.read())
                pd = perm_xml['PermissionDefinitions']['permissionDef']
                for perm in pd:
                    targetKind = perm.get('@targetKind', '')
                    if targetKind == 'Method':
                        api_class = perm['@className']
                        api_name = perm['@target']
                        api_name = re.sub('(?<=\()(.*) ', '\1', api_name)
                        api = '<{}: {}>'.format(api_class, api_name)
                        pp = perm['permission']
                        if type(pp) is list:
                            for p in pp:
                                pname = p['@name']
                                pmapping.append('{};{}'.format(api, pname))
                        else:
                            pname = pp['@name']
                            pmapping.append('{};{}'.format(api, pname))
                    elif targetKind == 'Field':
                        fc += 1
print(fc)
with open(dest_file, 'w')as fd:
    fd.write('\n'.join(pmapping))
