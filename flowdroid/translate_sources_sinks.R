# require(stringr)
# sed -E 's/(^[^\)]*\)).*@DSSource\({?DSSourceKind\.([^})]*)}?\).*/\1;\2/g' /Volumes/Internal/workspace/droidsafe/modeling/api/working/scanning-source.0217 > ~/LAB/workspace/imdea/static_analysis_app/flowdroid/data/sources_droidsafe.txt
# sed -E 's/(^[^\)]*\)).*@DSSink\({?DSSinkKind\.([^})]*)}?\).*/\1;\2/g' /Volumes/Internal/workspace/droidsafe/modeling/api/working/scanning-sink.0217 > ~/LAB/workspace/imdea/static_analysis_app/flowdroid/data/sinks_droidsafe.txt
require(data.table)
out.root="/Users/kuznetsov/LAB/workspace/imdea/static_analysis_app/flowdroid/data/"
sources.file="/Users/kuznetsov/LAB/workspace/imdea/static_analysis_app/flowdroid/data/sources_droidsafe.txt"
sinks.file="/Users/kuznetsov/LAB/workspace/imdea/static_analysis_app/flowdroid/data/sinks_droidsafe.txt"
log.name=paste0(out.root,"sources_sinks_translation_log.txt")
logFile=file(log.name)
log.list=c()
droidsafe.full.file="/Users/kuznetsov/LAB/workspace/imdea/static_analysis_app/flowdroid/data/SourcesAndSinksDroidSafe.txt"
droidsafe.full=read.table(droidsafe.full.file,blank.lines.skip = TRUE, sep='-',comment.char="%",stringsAsFactors=F,strip.white=TRUE)
droidsafe.full=unique(droidsafe.full)
droidsafe.full=data.table(droidsafe.full)
names(droidsafe.full)<-c('api','type')
droidsafe.full[,type:=sub('.*> _(.*)_','\\1',type)]
droidsafe.full[,classname:=sub("<(.+): .*?([^\\.]+) (.+)\\((.*)\\)>","\\2 \\1.\\3",api)]
droidsafe.full[,args:=sub("<(.+): .*?([^\\.]+) (.+)\\((.*)\\)>","\\4",api)]
droidsafe.full[,args:=gsub("[a-zA-Z]+\\.","",args)]
droidsafe.full[,signature:=paste0(classname,"(",args,")")]
setkey(droidsafe.full,signature)

droidsafe.sources=droidsafe.full[type=="SOURCE"]
droidsafe.sinks=droidsafe.full[type=="SINK"]

sources=fread(sources.file,sep=";")
names(sources)<-c('api','cat')
setkey(sources,api)
translated.sources=droidsafe.sources[sources]
log.list=append(log.list,paste("Number of sources:",nrow(sources)))
log.list=append(log.list,paste("Number of translated sources:",nrow(translated.sources)))
log.list=append(log.list,paste("Number of na sources",nrow(translated.sources[is.na(api)])))

sinks=fread(sinks.file,sep=";")
names(sinks)<-c('api','cat')
setkey(sinks,api)
translated.sinks=droidsafe.sinks[sinks]
log.list=append(log.list,paste("Number of sinks:",nrow(sinks)))
log.list=append(log.list,paste("Number of translated sinks:",nrow(translated.sinks)))
log.list=append(log.list,paste("Number of na sinks",nrow(translated.sinks[is.na(api)])))

fwrite(translated.sources[order(cat, api),.(api,cat)],file=paste0(out.root,"sources_category.txt"))
fwrite(translated.sinks[order(cat, api),.(api,cat)],file=paste0(out.root,"sinks_category.txt"))

sources.sens.na=translated.sources[is.na(api)]
sources.sens.uncat=translated.sources[!is.na(api)&cat=="SENSITIVE_UNCATEGORIZED"]
fwrite(sources.sens.na[order(cat, signature),.(cat,signature)],file=paste0(out.root,"sources_sens_na.txt"),quote=F)
fwrite(sources.sens.uncat[order(cat, api),.(cat,api)],file=paste0(out.root,"sources_sens_nocat.txt"),quote=F)
ex.source.list=c("SENSITIVE_UNCATEGORIZED","UNMODELED","NFC",
    "SYNCHRONIZATION_DATA","DATABASE_INFORMATION","BLUETOOTH_INFORMATION","GUI")
ex.class="com.android.internal"
sources.sens.full=translated.sources[!cat%in%ex.source.list]
sources.sens.full=sources.sens.full[grep(ex.class,api,invert=T)]
sources.sens.full=sources.sens.full[!is.na(api)]

sinks.sens.na=translated.sinks[is.na(api)]
sinks.sens.uncat=translated.sinks[!is.na(api)&cat=="SENSITIVE_UNCATEGORIZED"]
fwrite(sinks.sens.na[order(cat, signature),.(cat,signature)],file=paste0(out.root,"sinks_sens_na.txt"),quote=F)
fwrite(sinks.sens.uncat[order(cat, api),.(cat,api)],file=paste0(out.root,"sinks_sens_nocat.txt"),quote=F)
ex.sinks.list=c("SENSITIVE_UNCATEGORIZED","START_ACTIVITY","NFC",
    "SYNCHRONIZATION_DATA","BLUETOOTH","AUDIO","VOIP","SYSTEM_SETTINGS","LOCATION_INFORMATION")
sinks.sens.full=translated.sinks[!cat%in%ex.sinks.list]
sinks.sens.full=sinks.sens.full[grep(ex.class,api,invert=T)]
sinks.sens.full=sinks.sens.full[!is.na(api)]

writeLines(log.list, logFile)
close(logFile)

cat("*** Sources ***", file=log.name,append=TRUE,sep="\n")
fwrite(sources.sens.full[!is.na(api),.N,by=cat],file=log.name,append=T)
cat("*** Sinks ***", file=log.name,append=TRUE,sep="\n")
fwrite(sinks.sens.full[!is.na(api),.N,by=cat],file=log.name,append=T)
sources.sens.full[!is.na(api),.N,by=cat]
sinks.sens.full[!is.na(api),.N,by=cat]

fwrite(sources.sens.full[order(cat, api),.(cat,api)],file=paste0(out.root,"sources_sens_full.txt"),quote=F)
fwrite(sinks.sens.full[order(cat, api),.(cat,api)],file=paste0(out.root,"sinks_sens_full.txt"),quote=F)
