from jinja2 import Environment, PackageLoader, select_autoescape

from spid_sp_test import BASE_DIR, AbstractSpidCheck


class SpidSpResponseCheck(AbstractSpidCheck):    
    template_base_dir = f'{BASE_DIR}/responses/test/'


    def __init__(self, *args, **kwargs):
        super(SpidSpResponseCheck, self).__init__(*args, **kwargs)
        self.category = 'response'
        self.metadata_etree = kwargs.get('metadata_etree')
        self.authnreq_etree = kwargs.get('authnreq_etree')
        self.relay_state = kwargs.get('relay_state')
        
        self.loader = Environment(
                    loader = PackageLoader('responses', 'templates'),
                    autoescape = select_autoescape(['html', 'xml'])
        )

    def render(self, template:str='base.xml', data:dict={}):
        template = self.loader.get_template(template)
        self.logger.error(template.render(**data))
        


    def test_all(self):
        self.render()
    
