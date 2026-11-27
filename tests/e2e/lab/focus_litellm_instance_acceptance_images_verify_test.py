"""Two refusal gates at the exact images-verify acceptance boundary."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import focus_litellm_instance_acceptance_images_verify as v


def fixture():
    before={k:{} for k in ('catalogs','files','volumes','secrets','containers','external_containers','networks','units','timer')}
    before.update(running=['original'],package=False,config_directory=False,active_jobs=[],
                  images=[v.plan.APP_BASE],image_refs={'original:tag':v.plan.APP_BASE})
    before['containers']={'original':'1'*64};before['catalogs']={'original.json':'2'*64}
    derived='a'*64;name='woowbk_focus_litellm_a2c39e761b04'
    config={'architecture':'amd64','os':'linux','layers':['sha256:'+'b'*64],
            'volumes':None,'user':'65534','base':'','case':''}
    original={v.plan.APP_BASE:config};configs=copy.deepcopy(original)
    configs[derived]=dict(config,user='1000:0',base='sha256:'+v.plan.APP_BASE,case=name,
                         layers=config['layers']+['sha256:'+'c'*64])
    after=copy.deepcopy(before);after['images'].append(derived);after['image_refs'][v.plan.APP_TAG]=derived
    build={'before':copy.deepcopy(before),'after':copy.deepcopy(after),'verified':True,
           'result':{'ok':True,'terminal':True},'unknown_images':[],'owned_images':[derived],
           'iid':derived,'derivation_sha256':v.plan.DERIVATION_SHA,'configs_before':original,
           'configs_after':copy.deepcopy(configs)}
    hashes={'VERSION':'d'*64,'helper':'e'*64}
    facts={'name':name,'journal_unchanged':True,'state':{'before':copy.deepcopy(before),'image_build':build},
           'current':after,'configs':configs,'engine_hashes':hashes}
    return facts,{'before':before,'derived':derived,'source_hashes':hashes}


class ImagesVerifyTests(unittest.TestCase):
    def test_unknown_original_diff_refuses_readiness_even_with_valid_terminal_build(self):
        facts,args=fixture();self.assertTrue(v.verify(facts,**args))
        for field in ('catalogs','containers','files','volumes','secrets'):
            with self.subTest(field=field):
                changed=copy.deepcopy(facts);changed['current'][field]['foreign']='f'*64
                with self.assertRaisesRegex(ValueError,'original-inventory-diff'):v.verify(changed,**args)
        changed=copy.deepcopy(facts);changed['current']['containers']['headscale']='f'*64
        with self.assertRaisesRegex(ValueError,'original-inventory-diff'):v.verify(changed,**args)

    def test_unknown_image_or_label_refuses_despite_unchanged_original_apps(self):
        facts,args=fixture();self.assertTrue(v.verify(facts,**args));compile(v.program(),'<fixed verify>','exec')
        changed=copy.deepcopy(facts);changed['current']['images'].append('f'*64)
        with self.assertRaisesRegex(ValueError,'unknown-image-or-tag'):v.verify(changed,**args)
        changed=copy.deepcopy(facts)
        for configs in (changed['configs'],changed['state']['image_build']['configs_after']):
            configs[args['derived']]['case']='foreign-case'
        with self.assertRaisesRegex(ValueError,'derived-image-config-label-or-layers'):v.verify(changed,**args)
        changed=copy.deepcopy(facts);changed['current']['image_refs']['foreign:tag']=args['derived']
        with self.assertRaisesRegex(ValueError,'unknown-image-or-tag'):v.verify(changed,**args)


if __name__=='__main__':unittest.main()
