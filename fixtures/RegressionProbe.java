import java.io.*;
import java.nio.file.*;
import java.util.zip.*;
import java.lang.reflect.*;
/** Local regression probes. All writes stay under an OS temporary directory. No network. */
public class RegressionProbe {
 static byte[] read(InputStream in) throws IOException {ByteArrayOutputStream b=new ByteArrayOutputStream();byte[] buf=new byte[4096];int n;while((n=in.read(buf))!=-1)b.write(buf,0,n);return b.toByteArray();}
 public static void main(String[] args) throws Exception {
  String kind=args[0];
  if(kind.equals("commons-io")) {
   Class<?> c=Class.forName("org.apache.commons.io.FilenameUtils");
   for(String s:new String[]{"//../foo","\\\\..\\foo","dir/file.txt"})
    System.out.println(s+" => "+c.getMethod("normalize",String.class).invoke(null,s));
   return;
  }
  if(kind.equals("plexus-utils")) {
   Class<?> c=Class.forName("org.codehaus.plexus.util.cli.Commandline");
   Object cmd=c.getConstructor().newInstance();c.getMethod("setExecutable",String.class).invoke(cmd,"/bin/echo");
   Object arg=c.getMethod("createArg").invoke(cmd);
   // A literal dollar variable distinguishes shell interpretation from argument-vector execution.
   arg.getClass().getMethod("setValue",String.class).invoke(arg,"$PILOT_ONLY_MARKER");
   Process p=(Process)c.getMethod("execute").invoke(cmd);
   System.out.println("OUTPUT="+new String(read(p.getInputStream())).trim());
   System.out.println("EXIT="+p.waitFor());
   Path base=Files.createTempDirectory("plexus-pilot-");
   try {
    Path dir=base.resolve("space $PILOT_ONLY_MARKER");Files.createDirectories(dir);
    Path script=dir.resolve("tool.sh");Files.write(script,"#!/bin/sh\necho PILOT_SCRIPT_OK\n".getBytes("UTF-8"));script.toFile().setExecutable(true);
    Object cmd2=c.getConstructor().newInstance();c.getMethod("setExecutable",String.class).invoke(cmd2,script.toString());
    Process p2=(Process)c.getMethod("execute").invoke(cmd2);
    System.out.println("EXECUTABLE_OUTPUT="+new String(read(p2.getInputStream())).trim());
    System.out.println("EXECUTABLE_ERROR="+new String(read(p2.getErrorStream())).trim());
    System.out.println("EXECUTABLE_EXIT="+p2.waitFor());
   } finally {try(java.util.stream.Stream<Path> paths=Files.walk(base)){paths.sorted(java.util.Comparator.reverseOrder()).forEach(x->{try{Files.deleteIfExists(x);}catch(IOException e){throw new UncheckedIOException(e);}});}}
   return;
  }
  Path base=Files.createTempDirectory("java-cve-pilot-");
  try {
   for(String entry:new String[]{"good.txt","../outside.txt","../out-sibling.txt"}) {
    Path out=base.resolve(entry.equals("../out-sibling.txt")?"out":"extract");Files.createDirectories(out);
    Path zip=base.resolve("input.zip");
    try(ZipOutputStream z=new ZipOutputStream(Files.newOutputStream(zip))){z.putNextEntry(new ZipEntry(entry));z.write("PILOT_BENIGN_FIXTURE".getBytes());z.closeEntry();}
    String status="accepted";
    try {
     if(kind.equals("hutool"))Class.forName("cn.hutool.core.util.ZipUtil").getMethod("unzip",File.class,File.class).invoke(null,zip.toFile(),out.toFile());
     else if(kind.equals("zt-zip"))Class.forName("org.zeroturnaround.zip.ZipUtil").getMethod("unpack",File.class,File.class).invoke(null,zip.toFile(),out.toFile());
     else if(kind.equals("plexus-archiver")) {
      Object obj=Class.forName("org.codehaus.plexus.archiver.zip.ZipUnArchiver").getConstructor().newInstance();
      Class<?> logType=Class.forName("org.codehaus.plexus.logging.Logger");
      Object logger=Class.forName("org.codehaus.plexus.logging.console.ConsoleLogger").getConstructor(int.class,String.class).newInstance(4,"pilot");
      obj.getClass().getMethod("enableLogging",logType).invoke(obj,logger);
      obj.getClass().getMethod("setSourceFile",File.class).invoke(obj,zip.toFile());
      obj.getClass().getMethod("setDestDirectory",File.class).invoke(obj,out.toFile());
      obj.getClass().getMethod("extract").invoke(obj);
     }
     else if(kind.equals("zip4j")) {
      Object obj=Class.forName("net.lingala.zip4j.core.ZipFile").getConstructor(File.class).newInstance(zip.toFile());
      obj.getClass().getMethod("extractAll",String.class).invoke(obj,out.toString());
     }
    } catch(InvocationTargetException e){status="rejected:"+e.getCause().getClass().getSimpleName();}
    Path result=out.resolve(entry).normalize();
    System.out.println(entry+" => "+status+"; written="+Files.exists(result)+"; outside_extract="+!result.startsWith(out));
    Files.deleteIfExists(result);
   }
  } finally {
   try(java.util.stream.Stream<Path> s=Files.walk(base)) {s.sorted(java.util.Comparator.reverseOrder()).forEach(p->{try{Files.deleteIfExists(p);}catch(IOException e){throw new UncheckedIOException(e);}});}
  }
 }
}
