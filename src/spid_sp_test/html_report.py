import os
import logging
import shutil

from . import BASE_DIR

logger = logging.getLogger(__name__)


from jinja2 import (Environment,
                    FileSystemLoader,
                    select_autoescape)


def render_html_report(data:dict,
                       display_name:str,
                       template_search_path:str = f'{BASE_DIR}/html',
                       output_folder:str = './html_report'):
    loader = Environment(
                loader=FileSystemLoader(searchpath = template_search_path),
                autoescape=select_autoescape(['html'])
            )

    template = loader.get_template('index.html')

    page_fname = f'{output_folder}/index.html'
    try:
        os.mkdir(output_folder)
        shutil.copytree(f'{template_search_path}/static',
                        f'{output_folder}/static')
    except FileExistsError as e:
        logger.warning(e)

    f = open(page_fname, 'w')
    f.write(template.render(report_data = data,
                            display_name = display_name))
    f.close()
