import os #bibliote para trabalhar as pastas e arquivos
import nvdlib #biblioteca que trabalha api nist
import pandas as pd #biblioteca p/ trabalhar com dados
import matplotlib.pyplot as plt # biblioteca para criar graficos
from openpyxl import load_workbook
from openpyxl.drawing.image import Image
from datetime import datetime, timedelta
from openpyxl import Workbook

ativos = ["cpe:2.3:o:canonical:ubuntu_linux:24.04:*:*:*:lts:*:*:*",
        "cpe:2.3:o:redhat:enterprise_linux:7.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:clickhouse:clickhouse:24.3.3.102:*:*:*:*:*:*:*",
        "cpe:2.3:h:cisco:meraki_mx:-:*:*:*:*:*:*:*"
        ]

ultima_atualização = 'ultima_atualizacao.txt'

def ler_csv(ativos):
    if os.path.exists('cve.csv') and not precisa_atualizar(ultima_atualização):
        print('daos ainda recentes, carregando do arquivo..')
        df_antigo = pd.read_csv('cve.csv')
        print(f"{len(df_antigo)} cve's encontrados")
        return df_antigo
    if not os.path.exists(ultima_atualização):
        print("primeira execução, buscando todos os CVE's...")
        df_novo = carga_inicial(ativos)
    else:
        print("buscando CVE's novos desde o ultimo scan...")
        with open(ultima_atualização,'r') as f:
            ultimo_scan = datetime.fromisoformat(f.read().strip())
        print(f'{(datetime.now() - ultimo_scan).days} dias desde o ultimo scan')
        df_novo = ultimos_cves(ativos)

    if os.path.exists('cve.csv'):
        print("mesclando com dados anteries...")
        df_antigo = pd.read_csv('cve.csv')
        df = pd.concat([df_antigo, df_novo]).drop_duplicates(subset='cve_id')
        df = df.sort_values('publicado', ascending=False)
    else:
        df = df_novo

    registrar_scan(ultima_atualização)
    print(f"total: {len(df)} cve's")
    return df

dias_para_atualizar = 3

def precisa_atualizar(ultima_atualizacao):
    if not os.path.exists(ultima_atualizacao):
        return True
    with open(ultima_atualizacao,'r') as f:
        ultima = datetime.fromisoformat(f.read().strip())
    return datetime.now()- ultima > timedelta(days=dias_para_atualizar)

def registrar_scan(ultima_atualizacao):
    with open (ultima_atualizacao,'w') as f:
        f.write(datetime.now().isoformat())
    

def ultimos_cves(ativos):
    registros = []

    with open(ultima_atualização,'r') as f:
        ultimo_scan = datetime.fromisoformat(f.read().strip())

    for cpe in ativos:
        r = nvdlib.searchCVE(
            cpeName= cpe,
            pubStartDate= ultimo_scan,
            pubEndDate= datetime.now()
            )
        for cve in r:
            registros.append({
                'cpe'       : cpe.split(':')[4],
                'cve_id'    : cve.id,
                'score'     : cve.score[1] if cve.score else None,
                'severidade': cve.score[2] if cve.score else None,
                'publicado' :cve.published,
                'descricao' :cve.descriptions[0].value
            })
    cho = nvdlib.searchCVE(
        keywordSearch = "chromium",
        pubStartDate  = ultimo_scan,
        pubEndDate    = datetime.now()
    )
    for cve in cho:
        registros.append({
            'cpe'       : 'chromium',
            'cve_id'    : cve.id,
            'score'     : cve.score[1] if cve.score else None,
            'severidade': cve.score[2] if cve.score else None,
            'publicado' : cve.published,
            'descricao' : cve.descriptions[0].value
        })

    total_encontrados = len(registros)
    print(f"novos cve's encontrados desde {ultimo_scan.date()}: {total_encontrados}")
    for cve in registros:
        print(f"{cve['cve_id']}")
              
    df = pd.DataFrame(registros)
    df = df.drop_duplicates(subset='cve_id')
    df = df.sort_values('publicado', ascending=False)
    return df        


def carga_inicial(ativos):
    registros = []

    for cpe in ativos:
        r = nvdlib.searchCVE(
            cpeName = cpe 
        )

        for cve in r:
            registros.append({
                'cpe'       : cpe.split(':')[4],
                'cve_id'    : cve.id,
                'score'     : cve.score[1] if cve.score else None,
                'severidade': cve.score[2] if cve.score else None,
                'publicado' :cve.published,
                'descricao' :cve.descriptions[0].value
            })

    cho = nvdlib.searchCVE(keywordSearch="chromium")

    for cve in cho:
        registros.append({
            "cpe"       : "chromium",     
            "cve_id"    : cve.id,
            "score"     : cve.score[1] if cve.score else None,
            "severidade": cve.score[2] if cve.score else None,
            "publicado" : cve.published,
            "descricao" : cve.descriptions[0].value
        })

    df_inicial = pd.DataFrame(registros)
    df_inicial = df_inicial.sort_values('publicado', ascending=False)
    df_inicial = df_inicial[df_inicial['publicado'] > '2025-06-01']
    return df_inicial

def grava_dados(df):
    df.to_csv('cve.csv', index = False)
    #wb = Workbook()
    #ws = wb.active
    #for r in df.itertuples(index=False):
    #    ws.append(list(r))
    #wb.save('cves.xlsx')

def salva_excel(df):
    nome_arquivo = f'cves_{datetime.now().strftime("%Y%m%d")}.xlsx'
    df.to_excel(nome_arquivo, index = False, engine = 'openpyxl')




def main():
    df=ler_csv(ativos)
    return df
    
data = main()
grava_dados(data)
salva_excel(data)   
