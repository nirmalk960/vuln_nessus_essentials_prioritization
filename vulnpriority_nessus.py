import pandas as pd
import requests
import json
import glob
import dash_table
import dash_core_components as dcc
import dash_html_components as html
import urllib.parse
import dash_bootstrap_components as dbc
import dash
import datetime

url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
response = requests.get(url)
json_data = response.json()

data = json_data

cisa_df = pd.json_normalize(data, record_path=['vulnerabilities'])
cisa_kv_list = cisa_df['cveID'].tolist()

file_path = './nessus/'
file_extension = '*.csv'

file_list = glob.glob(file_path + file_extension)

vuln_res = pd.concat([pd.read_csv(f) for f in file_list])

vuln_res_df = vuln_res[vuln_res['CVE'].notnull()]
cisa_kv_report = vuln_res_df[vuln_res_df['CVE'].isin(cisa_kv_list)]
Exploitable_True = vuln_res[vuln_res['Metasploit'] == True]
print(cisa_kv_report)

def epss(CVE):
    current_date = datetime.datetime.now().date()
    formatted_date = current_date.strftime('%Y-%m-%d')
    response = requests.get('https://api.first.org/data/v1/epss?cve={}&date={}'.format(CVE,formatted_date))
    json2_data = response.json()
    epss_value = json2_data['data'][0]['epss']
    return epss_value

vuln_res_df['EPSS_SCORE'] = vuln_res_df['CVE'].apply(epss)
vuln_res_df['EPSS_SCORE'] = pd.to_numeric(vuln_res_df['EPSS_SCORE'], errors='coerce')
RISK_EPSS_df = vuln_res_df[vuln_res_df['EPSS_SCORE'] > 0.7]


app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
app.scripts.config.serve_locally = True
app.config['suppress_callback_exceptions'] = True

app.layout = html.Div(children=[
    html.Div([
        html.H1('Vulnerability Prioritization using CISA Known vulnerabilities and Exploit DB for Nessus Essentials Scan Results', style={'textAlign': 'center'})
    ]),
    html.Div([
        html.H4('Vulnerabilities to be Fixed on Priority Based on CISA Known Vulnerabilties',style={'textAlign': 'center'}),
                dash_table.DataTable(
                    id='CISA-DATA',
                    columns=[{"name": i, "id": i} for i in cisa_kv_report.columns],
                    style_header={'backgroundColor': 'rgb(144, 238, 144)', 'color': 'white'},
                    style_cell=dict(minWidth='180px', width='180px', maxWidth='180px', textAlign='left',
                                    backgroundColor='rgb(238, 226, 136)', color='black', overflow='hidden',
                                    textOverflow='ellipsis'),
                    style_table={'overflowX': 'auto'},
                    css=[{'selector': '.row', 'rule': 'margin: 0'}],
                    data=cisa_kv_report.to_dict('records'),
                    page_size=50,
                    style_cell_conditional=[
            {'if': {'column_id': c}, 'border': '5px solid white'} for c in cisa_kv_report.columns
        ]
                )
                ]),
    html.Div([
        html.H4('Vulnerabilities to be Fixed on Priority Based on FIRST EPSS Score > 0.7',style={'textAlign': 'center'}),
                dash_table.DataTable(
                    columns=[{"name": i, "id": i} for i in RISK_EPSS_df.columns],
                    style_header={'backgroundColor': 'rgb(173, 216, 230)', 'color': 'white'},
                    style_cell=dict(minWidth='180px', width='180px', maxWidth='180px', textAlign='left',
                                    backgroundColor='rgb(255, 182, 193)', color='black', overflow='hidden',
                                    textOverflow='ellipsis'),
                    style_table={'overflowX': 'auto'},
                    css=[{'selector': '.row', 'rule': 'margin: 0'}],
                    data=RISK_EPSS_df.to_dict('records'),
                    page_size=50,
                    style_cell_conditional=[
            {'if': {'column_id': c}, 'border': '5px solid white'} for c in RISK_EPSS_df.columns
        ]
                )
                ]),
    html.Div([
        html.H4('Vulnerabilities to be Fixed on Priority Based on Exploit DB', style={'textAlign': 'center'}),
                dash_table.DataTable(
                    columns=[{"name": i, "id": i} for i in Exploitable_True.columns],
                    style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
                    style_cell=dict(minWidth='180px', width='180px', maxWidth='180px', textAlign='left',
                                    backgroundColor='rgb(238, 226, 136)', color='black', overflow='hidden',
                                    textOverflow='ellipsis',
                                    ),
                    filter_action='native',
                    style_table={'overflowX': 'auto'},
                    css=[{'selector': '.row', 'rule': 'margin: 0'}],
                    data=Exploitable_True.to_dict('records'),
                    page_size=200,
                    style_cell_conditional=[
                    {'if': {'column_id': c}, 'border': '5px solid white'} for c in Exploitable_True.columns
        ]
                )
    ],style={'backgroundColor': 'lightyellow'})
],style={'backgroundColor': 'lightyellow'})


if __name__ == '__main__':
    app.run_server(debug=True)
