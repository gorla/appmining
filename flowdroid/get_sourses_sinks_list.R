require(stringr)
require(data.table)
out.root="/Users/kuznetsov/LAB/workspace/imdea/static_analysis_app/flowdroid/data/"
susi.cat.file="/Users/kuznetsov/LAB/workspace/backstage/backstage-gitlab/res/susi.txt"
droidsafe.file="/Users/kuznetsov/LAB/workspace/backstage/backstage-gitlab/res/SourcesAndSinksDroidSafe.txt"
susi.cat=fread(susi.cat.file,head=F)
names(susi.cat)<-c('api','cat')
flowrdoid.file="/Users/kuznetsov/LAB/workspace/soot-infoflow-android/SourcesAndSinks.txt"
flowdroid=read.table(flowrdoid.file,blank.lines.skip = TRUE, sep='-',comment.char="%",stringsAsFactors=F,strip.white=TRUE)
droidsafe=read.table(droidsafe.file,blank.lines.skip = TRUE, sep='-',comment.char="%",stringsAsFactors=F,strip.white=TRUE)
names(flowdroid)<-c('api','type')
flowdroid=data.table(flowdroid)
flowdroid[,type:=sub('.*> _(.*)_','\\1',type)]
flowdroid[,api:=sub('>.+','>',api)]
droidsafe=data.table(droidsafe)
names(droidsafe)<-c('api','type')
droidsafe[,type:=sub('.*> _(.*)_','\\1',type)]

setkey(flowdroid,api)
setkey(susi.cat,api)
flowdroid=unique(flowdroid)
susi.cat=unique(susi.cat)

strict.diff=flowdroid[susi.cat, nomatch=0]
fl.diff=susi.cat[flowdroid]
ds.diff=susi.cat[droidsafe, nomatch=0]
ds.counts=ds.diff[,.N,by=cat]
fl.diff[is.na(cat),cat:="NA"]
ds.diff[is.na(cat),cat:="NA"]
fl.counts=fl.diff[,.N,by=cat]
fwrite(fl.counts,file=paste0(out.root,"fl_stats.txt"),sep=";")
fwrite(ds.counts,file=paste0(out.root,"ds_stats.txt"),sep=";")
fl.na=fl.diff[cat=="NA"]
fwrite(fl.na,file=paste0(out.root,"fl_na.txt"),sep=";")
fl.no.cat=fl.diff[cat=="NO_CATEGORY"]
ds.filtr=ds.diff[!cat%in%c("NO_CATEGORY","NA")]
fl.filtr=fl.diff[!cat%in%c("NO_CATEGORY","NA")]
fwrite(setorder(ds.filtr,type,api),file=paste0(out.root,"ds_filt.txt"),sep=";")
fwrite(setorder(fl.filtr,type,api),file=paste0(out.root,"fl_filt.txt"),sep=";")
fwrite(no.cat,file=paste0(out.root,"fl_nocat.txt"),sep=";")
no.na=fl.diff[!is.na(cat)]

# flowdroid=fread(flowrdoid.file,blank.lines.skip = TRUE, sep='-', fill=T,head=F)
