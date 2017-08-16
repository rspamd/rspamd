local _ba='1.6.1'local aba,bba,cba,dba=next,type,select,pcall;local _ca,aca=setmetatable,getmetatable
local bca,cca=table.insert,table.sort;local dca,_da=table.remove,table.concat
local ada,bda,cda=math.randomseed,math.random,math.huge;local dda,__b,a_b=math.floor,math.max,math.min;local b_b=rawget
local c_b=table.unpack or unpack;local d_b,_ab=pairs,ipairs;local aab=os.clock;local bab={}
local function cab(dcb,_db)return dcb>_db end;local function dab(dcb,_db)return dcb<_db end
local function _bb(dcb,_db,adb)return(dcb<_db)and _db or
(dcb>adb and adb or dcb)end;local function abb(dcb,_db)return _db and true end
local function bbb(dcb)return not dcb end
local function cbb(dcb)local _db=0;for adb,bdb in d_b(dcb)do _db=_db+1 end;return _db end
local function dbb(dcb,_db,adb,...)local bdb;local cdb=adb or bab.identity;for ddb,__c in d_b(dcb)do
if not bdb then bdb=cdb(__c,...)else
local a_c=cdb(__c,...)bdb=_db(bdb,a_c)and bdb or a_c end end;return bdb end
local function _cb(dcb,_db,adb,bdb)for i=0,#dcb,_db do local cdb=bab.slice(dcb,i+1,i+_db)
if#cdb>0 then while
(#cdb<_db and bdb)do cdb[#cdb+1]=bdb end;adb(cdb)end end end
local function acb(dcb,_db,adb,bdb)
for i=0,#dcb,_db-1 do local cdb=bab.slice(dcb,i+1,i+_db)if
#cdb>0 and i+1 <#dcb then while(#cdb<_db and bdb)do cdb[#cdb+1]=bdb end
adb(cdb)end end end
local function bcb(dcb,_db,adb)if _db==0 then adb(dcb)end
for i=1,_db do dcb[_db],dcb[i]=dcb[i],dcb[_db]bcb(dcb,_db-
1,adb)dcb[_db],dcb[i]=dcb[i],dcb[_db]end end;local ccb=-1
function bab.clear(dcb)for _db in d_b(dcb)do dcb[_db]=nil end;return dcb end
function bab.each(dcb,_db,...)for adb,bdb in d_b(dcb)do _db(adb,bdb,...)end end
function bab.eachi(dcb,_db,...)
local adb=bab.sort(bab.select(bab.keys(dcb),function(bdb,cdb)return bab.isInteger(cdb)end))for bdb,cdb in _ab(adb)do _db(cdb,dcb[cdb],...)end end
function bab.at(dcb,...)local _db={}for adb,bdb in _ab({...})do
if bab.has(dcb,bdb)then _db[#_db+1]=dcb[bdb]end end;return _db end
function bab.count(dcb,_db)if bab.isNil(_db)then return bab.size(dcb)end;local adb=0
bab.each(dcb,function(bdb,cdb)if
bab.isEqual(cdb,_db)then adb=adb+1 end end)return adb end
function bab.countf(dcb,_db,...)return bab.count(bab.map(dcb,_db,...),true)end
function bab.cycle(dcb,_db)_db=_db or 1;if _db<=0 then return bab.noop end;local adb,bdb;local cdb=0
while true do
return
function()adb=adb and
aba(dcb,adb)or aba(dcb)
bdb=not bdb and adb or bdb;if _db then cdb=(adb==bdb)and cdb+1 or cdb
if cdb>_db then return end end;return adb,dcb[adb]end end end
function bab.map(dcb,_db,...)local adb={}
for bdb,cdb in d_b(dcb)do local ddb,__c,a_c=bdb,_db(bdb,cdb,...)adb[a_c and __c or ddb]=
a_c or __c end;return adb end;function bab.reduce(dcb,_db,adb)
for bdb,cdb in d_b(dcb)do if adb==nil then adb=cdb else adb=_db(adb,cdb)end end;return adb end;function bab.reduceby(dcb,_db,adb,bdb,...)return
bab.reduce(bab.select(dcb,bdb,...),_db,adb)end;function bab.reduceRight(dcb,_db,adb)return
bab.reduce(bab.reverse(dcb),_db,adb)end
function bab.mapReduce(dcb,_db,adb)
local bdb={}for cdb,ddb in d_b(dcb)do bdb[cdb]=not adb and ddb or _db(adb,ddb)
adb=bdb[cdb]end;return bdb end;function bab.mapReduceRight(dcb,_db,adb)
return bab.mapReduce(bab.reverse(dcb),_db,adb)end
function bab.include(dcb,_db)local adb=
bab.isFunction(_db)and _db or bab.isEqual;for bdb,cdb in d_b(dcb)do if adb(cdb,_db)then
return true end end;return false end
function bab.detect(dcb,_db)
local adb=bab.isFunction(_db)and _db or bab.isEqual;for bdb,cdb in d_b(dcb)do if adb(cdb,_db)then return bdb end end end
function bab.where(dcb,_db)
local adb=bab.select(dcb,function(bdb,cdb)
for ddb in d_b(_db)do if cdb[ddb]~=_db[ddb]then return false end end;return true end)return#adb>0 and adb or nil end
function bab.findWhere(dcb,_db)
local adb=bab.detect(dcb,function(bdb)for cdb in d_b(_db)do
if _db[cdb]~=bdb[cdb]then return false end end;return true end)return adb and dcb[adb]end
function bab.select(dcb,_db,...)local adb={}for bdb,cdb in d_b(dcb)do
if _db(bdb,cdb,...)then adb[#adb+1]=cdb end end;return adb end
function bab.reject(dcb,_db,...)local adb=bab.map(dcb,_db,...)local bdb={}for cdb,ddb in d_b(adb)do if not ddb then
bdb[#bdb+1]=dcb[cdb]end end;return bdb end
function bab.all(dcb,_db,...)return( (#bab.select(bab.map(dcb,_db,...),abb))==
cbb(dcb))end
function bab.invoke(dcb,_db,...)local adb={...}
return
bab.map(dcb,function(bdb,cdb)
if bab.isTable(cdb)then
if bab.has(cdb,_db)then
if
bab.isCallable(cdb[_db])then return cdb[_db](cdb,c_b(adb))else return cdb[_db]end else
if bab.isCallable(_db)then return _db(cdb,c_b(adb))end end elseif bab.isCallable(_db)then return _db(cdb,c_b(adb))end end)end
function bab.pluck(dcb,_db)return
bab.reject(bab.map(dcb,function(adb,bdb)return bdb[_db]end),bbb)end;function bab.max(dcb,_db,...)return dbb(dcb,cab,_db,...)end;function bab.min(dcb,_db,...)return
dbb(dcb,dab,_db,...)end
function bab.shuffle(dcb,_db)if _db then ada(_db)end
local adb={}
bab.each(dcb,function(bdb,cdb)local ddb=dda(bda()*bdb)+1;adb[bdb]=adb[ddb]
adb[ddb]=cdb end)return adb end
function bab.same(dcb,_db)
return
bab.all(dcb,function(adb,bdb)return bab.include(_db,bdb)end)and
bab.all(_db,function(adb,bdb)return bab.include(dcb,bdb)end)end;function bab.sort(dcb,_db)cca(dcb,_db)return dcb end
function bab.sortBy(dcb,_db,adb)
local bdb=_db or bab.identity
if bab.isString(_db)then bdb=function(ddb)return ddb[_db]end end;adb=adb or dab;local cdb={}
bab.each(dcb,function(ddb,__c)
cdb[#cdb+1]={value=__c,transform=bdb(__c)}end)
cca(cdb,function(ddb,__c)return adb(ddb.transform,__c.transform)end)return bab.pluck(cdb,'value')end
function bab.groupBy(dcb,_db,...)local adb={...}local bdb={}
bab.each(dcb,function(cdb,ddb)local __c=_db(cdb,ddb,c_b(adb))
if
bdb[__c]then bdb[__c][#bdb[__c]+1]=ddb else bdb[__c]={ddb}end end)return bdb end
function bab.countBy(dcb,_db,...)local adb={...}local bdb={}
bab.each(dcb,function(cdb,ddb)local __c=_db(cdb,ddb,c_b(adb))bdb[__c]=(
bdb[__c]or 0)+1 end)return bdb end
function bab.size(...)local dcb={...}local _db=dcb[1]if bab.isTable(_db)then return cbb(dcb[1])else
return cbb(dcb)end end;function bab.containsKeys(dcb,_db)
for adb in d_b(_db)do if not dcb[adb]then return false end end;return true end
function bab.sameKeys(dcb,_db)for adb in
d_b(dcb)do if not _db[adb]then return false end end;for adb in
d_b(_db)do if not dcb[adb]then return false end end
return true end
function bab.sample(dcb,_db,adb)_db=_db or 1;if _db<1 then return end;if _db==1 then if adb then ada(adb)end;return
dcb[bda(1,#dcb)]end;return
bab.slice(bab.shuffle(dcb,adb),1,_db)end
function bab.sampleProb(dcb,_db,adb)if adb then ada(adb)end;return
bab.select(dcb,function(bdb,cdb)return bda()<_db end)end;function bab.toArray(...)return{...}end
function bab.find(dcb,_db,adb)for i=adb or 1,#dcb do if
bab.isEqual(dcb[i],_db)then return i end end end
function bab.reverse(dcb)local _db={}for i=#dcb,1,-1 do _db[#_db+1]=dcb[i]end;return _db end;function bab.fill(dcb,_db,adb,bdb)bdb=bdb or bab.size(dcb)
for i=adb or 1,bdb do dcb[i]=_db end;return dcb end
function bab.selectWhile(dcb,_db,...)
local adb={}
for bdb,cdb in _ab(dcb)do if _db(bdb,cdb,...)then adb[bdb]=cdb else break end end;return adb end
function bab.dropWhile(dcb,_db,...)local adb
for bdb,cdb in _ab(dcb)do if not _db(bdb,cdb,...)then adb=bdb;break end end;if bab.isNil(adb)then return{}end;return bab.rest(dcb,adb)end
function bab.sortedIndex(dcb,_db,adb,bdb)local cdb=adb or dab;if bdb then bab.sort(dcb,cdb)end;for i=1,#dcb do if not
cdb(dcb[i],_db)then return i end end
return#dcb+1 end
function bab.indexOf(dcb,_db)for k=1,#dcb do if dcb[k]==_db then return k end end end
function bab.lastIndexOf(dcb,_db)local adb=bab.indexOf(bab.reverse(dcb),_db)if adb then return
#dcb-adb+1 end end;function bab.findIndex(dcb,_db,...)
for k=1,#dcb do if _db(k,dcb[k],...)then return k end end end
function bab.findLastIndex(dcb,_db,...)
local adb=bab.findIndex(bab.reverse(dcb),_db,...)if adb then return#dcb-adb+1 end end;function bab.addTop(dcb,...)
bab.each({...},function(_db,adb)bca(dcb,1,adb)end)return dcb end;function bab.push(dcb,...)bab.each({...},function(_db,adb)
dcb[#dcb+1]=adb end)
return dcb end
function bab.pop(dcb,_db)
_db=a_b(_db or 1,#dcb)local adb={}
for i=1,_db do local bdb=dcb[1]adb[#adb+1]=bdb;dca(dcb,1)end;return c_b(adb)end
function bab.unshift(dcb,_db)_db=a_b(_db or 1,#dcb)local adb={}for i=1,_db do local bdb=dcb[#dcb]
adb[#adb+1]=bdb;dca(dcb)end;return c_b(adb)end
function bab.pull(dcb,...)
for _db,adb in _ab({...})do for i=#dcb,1,-1 do
if bab.isEqual(dcb[i],adb)then dca(dcb,i)end end end;return dcb end
function bab.removeRange(dcb,_db,adb)local bdb=bab.clone(dcb)local cdb,ddb=(aba(bdb)),#bdb
if ddb<1 then return bdb end;_db=_bb(_db or cdb,cdb,ddb)
adb=_bb(adb or ddb,cdb,ddb)if adb<_db then return bdb end;local __c=adb-_db+1;local a_c=_db;while __c>0 do
dca(bdb,a_c)__c=__c-1 end;return bdb end
function bab.chunk(dcb,_db,...)if not bab.isArray(dcb)then return dcb end;local adb,bdb,cdb={},0
local ddb=bab.map(dcb,_db,...)
bab.each(ddb,function(__c,a_c)cdb=(cdb==nil)and a_c or cdb;bdb=(
(a_c~=cdb)and(bdb+1)or bdb)
if not adb[bdb]then adb[bdb]={dcb[__c]}else adb[bdb][
#adb[bdb]+1]=dcb[__c]end;cdb=a_c end)return adb end
function bab.slice(dcb,_db,adb)return
bab.select(dcb,function(bdb)return
(bdb>= (_db or aba(dcb))and bdb<= (adb or#dcb))end)end;function bab.first(dcb,_db)local adb=_db or 1
return bab.slice(dcb,1,a_b(adb,#dcb))end
function bab.initial(dcb,_db)
if _db and _db<0 then return end;return
bab.slice(dcb,1,_db and#dcb- (a_b(_db,#dcb))or#dcb-1)end;function bab.last(dcb,_db)if _db and _db<=0 then return end
return bab.slice(dcb,_db and
#dcb-a_b(_db-1,#dcb-1)or 2,#dcb)end;function bab.rest(dcb,_db)if _db and
_db>#dcb then return{}end
return bab.slice(dcb,
_db and __b(1,a_b(_db,#dcb))or 1,#dcb)end;function bab.nth(dcb,_db)
return dcb[_db]end;function bab.compact(dcb)return
bab.reject(dcb,function(_db,adb)return not adb end)end
function bab.flatten(dcb,_db)local adb=
_db or false;local bdb;local cdb={}
for ddb,__c in d_b(dcb)do
if bab.isTable(__c)then bdb=adb and __c or
bab.flatten(__c)
bab.each(bdb,function(a_c,b_c)cdb[#cdb+1]=b_c end)else cdb[#cdb+1]=__c end end;return cdb end
function bab.difference(dcb,_db)if not _db then return bab.clone(dcb)end;return
bab.select(dcb,function(adb,bdb)return not
bab.include(_db,bdb)end)end
function bab.union(...)return bab.uniq(bab.flatten({...}))end
function bab.intersection(dcb,...)local _db={...}local adb={}
for bdb,cdb in _ab(dcb)do if
bab.all(_db,function(ddb,__c)return bab.include(__c,cdb)end)then bca(adb,cdb)end end;return adb end
function bab.symmetricDifference(dcb,_db)return
bab.difference(bab.union(dcb,_db),bab.intersection(dcb,_db))end
function bab.unique(dcb)local _db={}for i=1,#dcb do if not bab.find(_db,dcb[i])then
_db[#_db+1]=dcb[i]end end;return _db end
function bab.isunique(dcb)return bab.isEqual(dcb,bab.unique(dcb))end
function bab.zip(...)local dcb={...}
local _db=bab.max(bab.map(dcb,function(bdb,cdb)return#cdb end))local adb={}for i=1,_db do adb[i]=bab.pluck(dcb,i)end;return adb end
function bab.append(dcb,_db)local adb={}for bdb,cdb in _ab(dcb)do adb[bdb]=cdb end;for bdb,cdb in _ab(_db)do
adb[#adb+1]=cdb end;return adb end
function bab.interleave(...)return bab.flatten(bab.zip(...))end;function bab.interpose(dcb,_db)return
bab.flatten(bab.zip(_db,bab.rep(dcb,#_db-1)))end
function bab.range(...)
local dcb={...}local _db,adb,bdb
if#dcb==0 then return{}elseif#dcb==1 then adb,_db,bdb=dcb[1],0,1 elseif#dcb==2 then
_db,adb,bdb=dcb[1],dcb[2],1 elseif#dcb==3 then _db,adb,bdb=dcb[1],dcb[2],dcb[3]end;if(bdb and bdb==0)then return{}end;local cdb={}
local ddb=__b(dda((adb-_db)/bdb),0)for i=1,ddb do cdb[#cdb+1]=_db+bdb*i end;if#cdb>0 then
bca(cdb,1,_db)end;return cdb end
function bab.rep(dcb,_db)local adb={}for i=1,_db do adb[#adb+1]=dcb end;return adb end;function bab.partition(dcb,_db,adb)if _db<=0 then return end
return coroutine.wrap(function()
_cb(dcb,_db or 1,coroutine.yield,adb)end)end;function bab.sliding(dcb,_db,adb)if
_db<=1 then return end
return coroutine.wrap(function()
acb(dcb,_db or 2,coroutine.yield,adb)end)end
function bab.permutation(dcb)return
coroutine.wrap(function()bcb(dcb,
#dcb,coroutine.yield)end)end;function bab.invert(dcb)local _db={}
bab.each(dcb,function(adb,bdb)_db[bdb]=adb end)return _db end
function bab.concat(dcb,_db,adb,bdb)
local cdb=bab.map(dcb,function(ddb,__c)return
tostring(__c)end)return _da(cdb,_db,adb or 1,bdb or#dcb)end;function bab.noop()return end;function bab.identity(dcb)return dcb end;function bab.constant(dcb)return
function()return dcb end end
function bab.memoize(dcb,_db)
local adb=_ca({},{__mode='kv'})local bdb=_db or bab.identity;return
function(...)local cdb=bdb(...)local ddb=adb[cdb]if not ddb then
adb[cdb]=dcb(...)end;return adb[cdb]end end;function bab.once(dcb)local _db=0;local adb={}
return function(...)_db=_db+1;if _db<=1 then adb={...}end
return dcb(c_b(adb))end end
function bab.before(dcb,_db)
local adb=0;local bdb={}return
function(...)adb=adb+1;if adb<=_db then bdb={...}end;return dcb(c_b(bdb))end end
function bab.after(dcb,_db)local adb,bdb=_db,0;return
function(...)bdb=bdb+1;if bdb>=adb then return dcb(...)end end end
function bab.compose(...)local dcb=bab.reverse{...}
return function(...)local _db,adb=true
for bdb,cdb in _ab(dcb)do if _db then _db=false
adb=cdb(...)else adb=cdb(adb)end end;return adb end end
function bab.pipe(dcb,...)return bab.compose(...)(dcb)end
function bab.complement(dcb)return function(...)return not dcb(...)end end;function bab.juxtapose(dcb,...)local _db={}
bab.each({...},function(adb,bdb)_db[#_db+1]=bdb(dcb)end)return c_b(_db)end
function bab.wrap(dcb,_db)return function(...)return
_db(dcb,...)end end
function bab.times(dcb,_db,...)local adb={}for i=1,dcb do adb[i]=_db(i,...)end;return adb end
function bab.bind(dcb,_db)return function(...)return dcb(_db,...)end end;function bab.bind2(dcb,_db)
return function(adb,...)return dcb(adb,_db,...)end end;function bab.bindn(dcb,...)local _db={...}
return function(...)return
dcb(c_b(bab.append(_db,{...})))end end
function bab.bindAll(dcb,...)local _db={...}
for adb,bdb in
_ab(_db)do local cdb=dcb[bdb]if cdb then dcb[bdb]=bab.bind(cdb,dcb)end end;return dcb end
function bab.uniqueId(dcb,...)ccb=ccb+1
if dcb then if bab.isString(dcb)then return dcb:format(ccb)elseif
bab.isFunction(dcb)then return dcb(ccb,...)end end;return ccb end
function bab.iterator(dcb,_db)return function()_db=dcb(_db)return _db end end
function bab.array(...)local dcb={}for _db in...do dcb[#dcb+1]=_db end;return dcb end;function bab.flip(dcb)return
function(...)return dcb(c_b(bab.reverse({...})))end end;function bab.over(...)
local dcb={...}
return function(...)local _db={}for adb,bdb in _ab(dcb)do _db[#_db+1]=bdb(...)end
return _db end end;function bab.overEvery(...)
local dcb=bab.over(...)
return function(...)return
bab.reduce(dcb(...),function(_db,adb)return _db and adb end)end end;function bab.overSome(...)
local dcb=bab.over(...)
return function(...)return
bab.reduce(dcb(...),function(_db,adb)return _db or adb end)end end
function bab.overArgs(dcb,...)
local _db={...}return
function(...)local adb={...}for i=1,#_db do local bdb=_db[i]
if adb[i]then adb[i]=bdb(adb[i])end end;return dcb(c_b(adb))end end
function bab.partial(dcb,...)local _db={...}
return
function(...)local adb={...}local bdb={}for cdb,ddb in _ab(_db)do bdb[cdb]=
(ddb=='_')and bab.pop(adb)or ddb end;return
dcb(c_b(bab.append(bdb,adb)))end end
function bab.partialRight(dcb,...)local _db={...}
return
function(...)local adb={...}local bdb={}
for k=1,#_db do bdb[k]=
(_db[k]=='_')and bab.pop(adb)or _db[k]end;return dcb(c_b(bab.append(adb,bdb)))end end
function bab.curry(dcb,_db)_db=_db or 2;local adb={}
local function bdb(cdb)if _db==1 then return dcb(cdb)end;if cdb~=nil then
adb[#adb+1]=cdb end;if#adb<_db then return bdb else local ddb={dcb(c_b(adb))}adb={}return
c_b(ddb)end end;return bdb end
function bab.time(dcb,...)local _db=aab()local adb={dcb(...)}return aab()-_db,c_b(adb)end;function bab.keys(dcb)local _db={}
bab.each(dcb,function(adb)_db[#_db+1]=adb end)return _db end;function bab.values(dcb)local _db={}
bab.each(dcb,function(adb,bdb)_db[
#_db+1]=bdb end)return _db end;function bab.kvpairs(dcb)local _db={}
bab.each(dcb,function(adb,bdb)_db[
#_db+1]={adb,bdb}end)return _db end
function bab.toObj(dcb)local _db={}for adb,bdb in
_ab(dcb)do _db[bdb[1]]=bdb[2]end;return _db end
function bab.property(dcb)return function(_db)return _db[dcb]end end
function bab.propertyOf(dcb)return function(_db)return dcb[_db]end end;function bab.toBoolean(dcb)return not not dcb end
function bab.extend(dcb,...)local _db={...}
bab.each(_db,function(adb,bdb)if
bab.isTable(bdb)then
bab.each(bdb,function(cdb,ddb)dcb[cdb]=ddb end)end end)return dcb end
function bab.functions(dcb,_db)dcb=dcb or bab;local adb={}
bab.each(dcb,function(cdb,ddb)if bab.isFunction(ddb)then
adb[#adb+1]=cdb end end)if not _db then return bab.sort(adb)end;local bdb=aca(dcb)
if
bdb and bdb.__index then local cdb=bab.functions(bdb.__index)bab.each(cdb,function(ddb,__c)
adb[#adb+1]=__c end)end;return bab.sort(adb)end
function bab.clone(dcb,_db)if not bab.isTable(dcb)then return dcb end;local adb={}
bab.each(dcb,function(bdb,cdb)if
bab.isTable(cdb)then
if not _db then adb[bdb]=bab.clone(cdb,_db)else adb[bdb]=cdb end else adb[bdb]=cdb end end)return adb end;function bab.tap(dcb,_db,...)_db(dcb,...)return dcb end;function bab.has(dcb,_db)return
dcb[_db]~=nil end
function bab.pick(dcb,...)local _db=bab.flatten{...}
local adb={}
bab.each(_db,function(bdb,cdb)
if not bab.isNil(dcb[cdb])then adb[cdb]=dcb[cdb]end end)return adb end
function bab.omit(dcb,...)local _db=bab.flatten{...}local adb={}
bab.each(dcb,function(bdb,cdb)if
not bab.include(_db,bdb)then adb[bdb]=cdb end end)return adb end;function bab.template(dcb,_db)
bab.each(_db or{},function(adb,bdb)if not dcb[adb]then dcb[adb]=bdb end end)return dcb end
function bab.isEqual(dcb,_db,adb)
local bdb=bba(dcb)local cdb=bba(_db)if bdb~=cdb then return false end
if bdb~='table'then return(dcb==_db)end;local ddb=aca(dcb)local __c=aca(_db)if adb then
if
(ddb or __c)and(ddb.__eq or __c.__eq)then return
ddb.__eq(dcb,_db)or __c.__eq(_db,dcb)or(dcb==_db)end end;if bab.size(dcb)~=
bab.size(_db)then return false end;for a_c,b_c in d_b(dcb)do local c_c=_db[a_c]
if
bab.isNil(c_c)or not bab.isEqual(b_c,c_c,adb)then return false end end
for a_c,b_c in d_b(_db)do
local c_c=dcb[a_c]if bab.isNil(c_c)then return false end end;return true end
function bab.result(dcb,_db,...)
if dcb[_db]then if bab.isCallable(dcb[_db])then return dcb[_db](dcb,...)else return
dcb[_db]end end;if bab.isCallable(_db)then return _db(dcb,...)end end;function bab.isTable(dcb)return bba(dcb)=='table'end
function bab.isCallable(dcb)return
(
bab.isFunction(dcb)or
(bab.isTable(dcb)and aca(dcb)and aca(dcb).__call~=nil)or false)end
function bab.isArray(dcb)if not bab.isTable(dcb)then return false end;local _db=0
for adb in
d_b(dcb)do _db=_db+1;if bab.isNil(dcb[_db])then return false end end;return true end
function bab.isIterable(dcb)return bab.toBoolean((dba(d_b,dcb)))end
function bab.isEmpty(dcb)if bab.isNil(dcb)then return true end;if bab.isString(dcb)then
return#dcb==0 end
if bab.isTable(dcb)then return aba(dcb)==nil end;return true end;function bab.isString(dcb)return bba(dcb)=='string'end;function bab.isFunction(dcb)return
bba(dcb)=='function'end;function bab.isNil(dcb)
return dcb==nil end
function bab.isNumber(dcb)return bba(dcb)=='number'end
function bab.isNaN(dcb)return bab.isNumber(dcb)and dcb~=dcb end
function bab.isFinite(dcb)if not bab.isNumber(dcb)then return false end;return
dcb>-cda and dcb<cda end;function bab.isBoolean(dcb)return bba(dcb)=='boolean'end
function bab.isInteger(dcb)return
bab.isNumber(dcb)and dda(dcb)==dcb end
do bab.forEach=bab.each;bab.forEachi=bab.eachi;bab.loop=bab.cycle
bab.collect=bab.map;bab.inject=bab.reduce;bab.foldl=bab.reduce
bab.injectr=bab.reduceRight;bab.foldr=bab.reduceRight;bab.mapr=bab.mapReduce
bab.maprr=bab.mapReduceRight;bab.any=bab.include;bab.some=bab.include;bab.contains=bab.include
bab.filter=bab.select;bab.discard=bab.reject;bab.every=bab.all
bab.takeWhile=bab.selectWhile;bab.rejectWhile=bab.dropWhile;bab.shift=bab.pop;bab.remove=bab.pull
bab.rmRange=bab.removeRange;bab.chop=bab.removeRange;bab.sub=bab.slice;bab.head=bab.first
bab.take=bab.first;bab.tail=bab.rest;bab.skip=bab.last;bab.without=bab.difference
bab.diff=bab.difference;bab.symdiff=bab.symmetricDifference;bab.xor=bab.symmetricDifference
bab.uniq=bab.unique;bab.isuniq=bab.isunique;bab.transpose=bab.zip;bab.part=bab.partition
bab.perm=bab.permutation;bab.mirror=bab.invert;bab.join=bab.concat;bab.cache=bab.memoize
bab.juxt=bab.juxtapose;bab.uid=bab.uniqueId;bab.iter=bab.iterator;bab.methods=bab.functions
bab.choose=bab.pick;bab.drop=bab.omit;bab.defaults=bab.template;bab.compare=bab.isEqual end
do local dcb={}local _db={}_db.__index=dcb;local function adb(bdb)local cdb={_value=bdb,_wrapped=true}
return _ca(cdb,_db)end
_ca(_db,{__call=function(bdb,cdb)return adb(cdb)end,__index=function(bdb,cdb,...)return
dcb[cdb]end})function _db.chain(bdb)return adb(bdb)end
function _db:value()return self._value end;dcb.chain,dcb.value=_db.chain,_db.value
for bdb,cdb in d_b(bab)do
dcb[bdb]=function(ddb,...)local __c=bab.isTable(ddb)and
ddb._wrapped or false
if __c then
local a_c=ddb._value;local b_c=cdb(a_c,...)return adb(b_c)else return cdb(ddb,...)end end end
dcb.import=function(bdb,cdb)bdb=bdb or _ENV or _G;local ddb=bab.functions()
bab.each(ddb,function(__c,a_c)
if
b_b(bdb,a_c)then if not cdb then bdb[a_c]=bab[a_c]end else bdb[a_c]=bab[a_c]end end)return bdb end;_db._VERSION='Moses v'.._ba
_db._URL='http://github.com/Yonaba/Moses'
_db._LICENSE='MIT <http://raw.githubusercontent.com/Yonaba/Moses/master/LICENSE>'_db._DESCRIPTION='utility-belt library for functional programming in Lua'return
_db end