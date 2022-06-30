#!/usr/bin/env python
# coding: utf-8

# In[36]:


import pandas as pd
from pycaret.classification import *
from anonymizeip import anonymize_ip
import warnings

warnings.filterwarnings("ignore")

sample = True 
binary = False 


import sys, os

# Disable
def blockPrint():
    sys.stdout = open(os.devnull, 'w')

# Restore
def enablePrint():
    sys.stdout = sys.__stdout__

# In[ ]:

blockPrint()

df = pd.read_csv("NF-ToN-IoT.csv")


# In[ ]:


df.columns


# In[35]:


# Remove non-ipfix standardized features
# See: https://www.ntop.org/guides/nprobe/cli_options.html#netflow-v9-ipfix-format-t
# Thesis: Refer to table 2 for feature names and descriptions

df_ipfix = df[['IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'L4_SRC_PORT', 'L4_DST_PORT', 'PROTOCOL', 'L7_PROTO', 'IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'TCP_FLAGS', 'FLOW_DURATION_MILLISECONDS', 'Label', 'Attack']]
df_ipfix.dtypes
df_ipfix['IPV4_SRC_ADDR'] = df_ipfix['IPV4_SRC_ADDR'].astype('category')
df_ipfix['IPV4_DST_ADDR'] = df_ipfix['IPV4_DST_ADDR'].astype('category')
df_ipfix['L4_SRC_PORT'] = df_ipfix['L4_SRC_PORT'].astype('uint16')
df_ipfix['L4_DST_PORT'] = df_ipfix['L4_DST_PORT'].astype('uint16')


# In[ ]:


df_ipfix.head()


# In[ ]:


if(binary):
    df_ = df_ipfix.drop("Attack", axis=1)
else:
    df_ = df_ipfix.drop("Label", axis=1)

# Samples
if(sample):
    df_ = df_.sample(n=10000)

df['Label'].value_counts()


# ## Feature Anonymization

# ### IP-address anonymization 

# In[ ]:


#pd.set_option("display.max_rows", None)

# /24 network address truncation

if(0):
    df_['IPV4_DST_ADDR'] = df_['IPV4_DST_ADDR'].apply(lambda x: anonymize_ip(x))
    df_['IPV4_SRC_ADDR'] = df_['IPV4_SRC_ADDR'].apply(lambda x: anonymize_ip(x))

# black-marker anonymization
if(0):
    df_['IPV4_SRC_ADDR'] = 0
    df_['IPV4_DST_ADDR'] = 0
    df_['IPV4_SRC_ADDR'] = df_['IPV4_SRC_ADDR'].astype(str) 
    df_['IPV4_DST_ADDR'] = df_['IPV4_DST_ADDR'].astype(str)
    df_.dtypes

df_.head()
df_['IPV4_SRC_ADDR'].value_counts()


# In[ ]:


session_binary = setup(df_, target = 'Attack', silent=True, experiment_name='binary', categorical_features = ['IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'L4_SRC_PORT', 'L4_DST_PORT', 'PROTOCOL', 'L7_PROTO', 'TCP_FLAGS'])


# In[ ]:


k = create_model('knn')
results = pull()
enablePrint()

print(results)

