#include <vector>
#include <string>

#include "voms_api.h"
#include "jni-int.h"

#include <unistd.h>

static jfieldID  vd_fid_d = 0;
static jfieldID  vd_fid_data = 0;

static jclass    dp_class = 0;
static jmethodID dp_constructor = 0;

static jclass    vp_class = 0;
static jmethodID vp_constructor = 0;
static jfieldID  vp_version  = 0;
static jfieldID  vp_siglen   = 0;
static jfieldID  vp_sign     = 0;
static jfieldID  vp_user     = 0;
static jfieldID  vp_userca   = 0;
static jfieldID  vp_server   = 0;
static jfieldID  vp_serverca = 0;
static jfieldID  vp_voname   = 0;
static jfieldID  vp_date1    = 0;
static jfieldID  vp_date2    = 0;
static jfieldID  vp_type     = 0;
static jfieldID  vp_std      = 0;
static jfieldID  vp_custom   = 0;
static jfieldID  vp_fqan     = 0;
static jfieldID  vp_serial   = 0;
static jfieldID  vp_holder   = 0;
static jfieldID  vp_issuer   = 0;
static jfieldID  vp_uri      = 0;

static jclass    cdp_class     = 0;
static jmethodID cdp_constructor = 0;

static jclass    s_class = 0;
static jmethodID s_constructor = 0;

static jboolean returnBool(JNIEnv *env, bool v)
{
  return (jboolean)v;
}

static void printString(JNIEnv *env, jstring str)
{
  const char *cname = env->GetStringUTFChars(str, 0);
  fprintf(stderr, "printString: %s\n", cname);
  env->ReleaseStringUTFChars(str, cname);
}

static jstring returnString(JNIEnv *env, std::string str)
{
  fprintf(stderr, "Creating string from: %s\n", str.c_str());

  jchar *jcs = (jchar *)malloc(str.size()*sizeof(jchar));
  if (!jcs)
    return NULL;

  fprintf(stderr, "creating\n");
  for (int i = 0; i < str.size(); i++)
    jcs[i] = str[i];

  return env->NewString(jcs, str.size());
}

static jbyteArray returnByteArray(JNIEnv *env, const char *data, int len)
{
  jbyteArray arr = env->NewByteArray(len);

  env->SetByteArrayRegion(arr, 0, len, (jbyte*)data);

  return arr;
}

static jobjectArray returnDataPeer(JNIEnv *env, std::vector<data> &data)
{
  jobjectArray arr = (jobjectArray)env->NewObjectArray(data.size(), cdp_class, NULL);

  for (int i = 0; i < data.size(); i++) {
    jobject obj = env->NewObject(cdp_class, cdp_constructor, 
                                 returnString(env, data[i].group),
                                 returnString(env, data[i].role),
                                 returnString(env, data[i].cap));
    env->SetObjectArrayElement(arr, i, obj);
  }

  return arr;
}

static jobjectArray returnContactData(JNIEnv *env, std::vector<contactdata> &array)
{
  fprintf(stderr, "in returnContactData\n");
  fprintf(stderr, "dp_class = %d\n", dp_class);
  fprintf(stderr, "size = %d\n",array.size());
  jobjectArray arr = (jobjectArray)env->NewObjectArray(array.size(), dp_class, NULL);
  fprintf(stderr, "Initialized array\n");

  for (int i = 0; i <array.size(); i++) {
    fprintf(stderr, "data: nick %s, host %s, contact:%s, port:%d\n", array[i].nick.c_str(), 
            array[i].host.c_str(), array[i].contact.c_str(),
            array[i].port);
    jobject obj = env->NewObject(dp_class, dp_constructor, 
                                 returnString(env, array[i].nick),
                                 returnString(env, array[i].host),
                                 returnString(env, array[i].contact), 
                                 array[i].port, array[i].version);
    fprintf(stderr, "Created object\n");
    env->SetObjectArrayElement(arr, i, obj);
    fprintf(stderr, "Added object\n");
  }

  return arr;
}

static jobjectArray returnStringArray(JNIEnv *env, std::vector<std::string> &array)
{
  std::vector<std::string>::iterator i = array.begin();
  std::vector<jobject> objarray;

  while (i != array.end()) {
    jstring obj = returnString(env, *i);

    objarray.push_back(obj);
    i++;
  }

  jobjectArray arr = (jobjectArray)env->NewObjectArray(objarray.size(), 
                                                       s_class, 
                                                       env->NewObject(s_class, 
                                                                      s_constructor));

  for (int i = 0; i <objarray.size(); i++)
    env->SetObjectArrayElement(arr, i, objarray[i]);

  if (arr)
    fprintf(stderr, "Created string array\n");
  return arr;
}

static jobject returnVomsPeer(JNIEnv *env, voms &v)
{
  AC *ac = v.GetAC();
  AC_HOLDER *h = ac->acinfo->holder;
  AC_FORM   *f = ac->acinfo->form;
  int holdlen = i2d_AC_HOLDER(h, 0);
  unsigned char *holdbuffer = (unsigned char *)malloc(holdlen);
  unsigned char *origholdbuffer = holdbuffer;

  int flen = i2d_AC_FORM(f, 0);
  unsigned char *fbuffer = (unsigned char *)malloc(flen);
  unsigned char *origfbuffer = fbuffer;
  if (!holdbuffer || !fbuffer || !(holdlen >0) || !(flen >0)) {
    return NULL;
  }
 
  i2d_AC_HOLDER(h, &origholdbuffer);
  i2d_AC_FORM(f, &origfbuffer);

  fprintf(stderr, "Making voms peer\n");
  jobject obj = env->NewObject(vp_class, vp_constructor);

  env->SetIntField   (obj, vp_version,  v.version);
  env->SetIntField   (obj, vp_siglen,   v.siglen);
  fprintf(stderr, "siglen: %d\n", v.siglen);

  env->SetObjectField(obj, vp_sign,     returnByteArray(env, v.signature.data(),
                                                        v.signature.size()));
  env->SetObjectField(obj, vp_user,     returnString(env, v.user));
  env->SetObjectField(obj, vp_userca,   returnString(env, v.userca));
  env->SetObjectField(obj, vp_server,   returnString(env, v.server));
  env->SetObjectField(obj, vp_serverca, returnString(env, v.serverca));
  env->SetObjectField(obj, vp_voname,   returnString(env, v.voname));
  env->SetObjectField(obj, vp_date1,    returnString(env, v.date1));
  env->SetObjectField(obj, vp_date2,    returnString(env, v.date2));
  env->SetIntField   (obj, vp_type,     v.type);
  env->SetObjectField(obj, vp_user,     returnString(env, v.user));
  env->SetObjectField(obj, vp_std,      returnDataPeer(env, v.std));
  env->SetObjectField(obj, vp_custom,   returnString(env, v.custom));
  env->SetObjectField(obj, vp_fqan,     returnStringArray(env, v.fqan));
  env->SetObjectField(obj, vp_serial,   returnString(env, v.serial));
  env->SetObjectField(obj, vp_holder,   returnByteArray(env, (const char *)holdbuffer, holdlen));
  env->SetObjectField(obj, vp_issuer,   returnByteArray(env, (const char *)fbuffer, flen));
  env->SetObjectField(obj, vp_uri,      returnString(env, v.uri));
  free(fbuffer);
  free(holdbuffer);

  fprintf(stderr, "Made voms peer\n");

  return obj;
}

static jobjectArray returnVomsPeerArray(JNIEnv *env, std::vector<voms> &array)
{
  jobjectArray arr = (jobjectArray)env->NewObjectArray(array.size(), vp_class, NULL);

  for (int i = 0; i < array.size(); i++)
    env->SetObjectArrayElement(arr, i, returnVomsPeer(env, array[i]));

  return arr;
}

JNIEXPORT jboolean JNICALL 
Java_org_glite_security_voms_peers_VomsdataPeer_LoadSystemContacts(JNIEnv *env, jobject obj, jstring jstr)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  jsize len = env->GetStringUTFLength(jstr);

  if (!len)
    return returnBool(env, vd->LoadSystemContacts());
  else {
    const char *cname = env->GetStringUTFChars(jstr,0);
    jboolean res = returnBool(env, vd->LoadSystemContacts(std::string(cname)));
    env->ReleaseStringUTFChars(jstr, cname);
    return res;
  }
}

JNIEXPORT jboolean JNICALL 
Java_org_glite_security_voms_peers_VomsdataPeer_LoadUserContacts(JNIEnv *env, jobject obj, jstring jstr)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  jsize len = env->GetStringUTFLength(jstr);

  if (!len)
    return returnBool(env, vd->LoadUserContacts());
  else {
    const char *cname = env->GetStringUTFChars(jstr,0);
    jboolean res = returnBool(env, vd->LoadUserContacts(std::string(cname)));
    env->ReleaseStringUTFChars(jstr, cname);
    return res;
  }
}

JNIEXPORT jobjectArray JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_FindByAlias(JNIEnv *env, jobject obj, jstring str)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  const char *cname = env->GetStringUTFChars(str, 0);
  std::vector<contactdata> r = vd->FindByAlias(std::string(cname));
  jobjectArray res = returnContactData(env, r);
  env->ReleaseStringUTFChars(str, cname);
  return res;
}

JNIEXPORT jobjectArray JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_FindByVO(JNIEnv *env, jobject obj, jstring str)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  fprintf(stderr, "sl = %d\n", sl);
  vomsdata *vd = (vomsdata *)sl;

  
  const char *cname = env->GetStringUTFChars(str, 0);
  fprintf(stderr, "cname = %s\n", cname);
  std::vector<contactdata> r = vd->FindByVO(std::string(cname));
  fprintf(stderr, "called FindByVO\n");
  jobjectArray res = returnContactData(env, r);
  fprintf(stderr, "called returnContactData\n");
  env->ReleaseStringUTFChars(str, cname);
  fprintf(stderr, "released chars\n");
  return res;
}

JNIEXPORT void JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_Order(JNIEnv *env, jobject obj, jstring str)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  const char *cname = env->GetStringUTFChars(str, 0);
  vd->Order(std::string(cname));
  env->ReleaseStringUTFChars(str, cname);
}

JNIEXPORT void JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_ResetOrder(JNIEnv *env, jobject obj)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  vd->ResetOrder();
}

JNIEXPORT void JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_AddTarget(JNIEnv *env, jobject obj, jstring str)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  const char *cname = env->GetStringUTFChars(str, 0);
  vd->AddTarget(std::string(cname));
  env->ReleaseStringUTFChars(str, cname);
}

JNIEXPORT jobjectArray JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_ListTargets(JNIEnv *env, jobject obj)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;
  std::vector<std::string> targets = vd->ListTargets();

  return returnStringArray(env, targets);
}

JNIEXPORT void JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_ResetTargets(JNIEnv *env, jobject obj)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  vd->ResetTargets();
}

JNIEXPORT jstring JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_ServerErrors(JNIEnv *env, jobject obj)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  std::string errmsg = vd->ServerErrors();
  return returnString(env, errmsg);
}

JNIEXPORT jboolean JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_RetrieveReal(JNIEnv *env, jobject obj, jbyteArray cert, jobjectArray chain, jint how)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  jbyte *arr = env->GetByteArrayElements(cert, NULL);
  X509 *realcert = d2i_X509(NULL, &((unsigned char *)arr), env->GetArrayLength(cert));
  env->ReleaseByteArrayElements(cert, arr, JNI_ABORT);

  STACK_OF(X509) *stack = sk_X509_new_null();

  for (int j = 0; j < env->GetArrayLength(chain); j++) {
    jbyteArray thisCert = (jbyteArray)env->GetObjectArrayElement(chain, j);
    jbyte *arr = env->GetByteArrayElements(thisCert, NULL);

    X509 *pcert = d2i_X509(NULL, &((unsigned char *)arr), env->GetArrayLength(thisCert));
    sk_X509_push(stack, pcert);

    env->ReleaseByteArrayElements(thisCert, arr, JNI_ABORT);
  }

  bool res = vd->Retrieve(realcert, stack, recurse_type(how));

  X509_free(realcert);
  sk_X509_free(stack);

  env->SetObjectField(obj, vd_fid_data, returnVomsPeerArray(env, vd->data));

  return returnBool(env, res);
}

JNIEXPORT jboolean JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_Contact(JNIEnv *env, jobject obj, jstring host, jint port, jstring servsubj, jstring command)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  const char *hostname = env->GetStringUTFChars(host, 0);
  const char *subject  = env->GetStringUTFChars(servsubj, 0);
  const char *vcommand = env->GetStringUTFChars(command, 0);

  fprintf(stderr, "CONTACT\n\nhost: %s\nsubj: %s\ncomm: %s\n\n", hostname,
          subject, vcommand);

  bool res = vd->Contact(hostname, port, subject, vcommand);
  fprintf(stderr, "res: %d\n", res);
  env->SetObjectField(obj, vd_fid_data, returnVomsPeerArray(env, vd->data));

  env->ReleaseStringUTFChars(host, hostname);
  env->ReleaseStringUTFChars(servsubj, subject);
  env->ReleaseStringUTFChars(command, vcommand);

  return returnBool(env, res);
}

JNIEXPORT void JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_SetVerificationType(JNIEnv *env, jobject obj, jint value)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  vd->SetVerificationType(verify_type((int)value));
}

JNIEXPORT void JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_SetLifetime(JNIEnv *env, jobject obj, jint value)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  int v = (int)value;
  vd->SetLifetime(v);
}

JNIEXPORT jboolean JNICALL Java_org_glite_security_voms_peers_VomsdataPeer_Import(JNIEnv *env, jobject obj, jstring str)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  const char *data = env->GetStringUTFChars(str, 0);
  int len = env->GetStringUTFLength(str);

  std::string idata = std::string(data, len);

  bool res = vd->Import(idata);

  env->ReleaseStringUTFChars(str, data);

  return returnBool(env, res);
}

JNIEXPORT jbyteArray JNICALL 
Java_org_glite_security_voms_peers_VomsdataPeer_ExportReal(JNIEnv *env, jobject obj)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  std::string odata;

  bool res = vd->Export(odata);

  if (res)
    return returnByteArray(env, odata.data(), odata.size());
  else
    return NULL;
}

JNIEXPORT jobject JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_DefaultDataReal(JNIEnv *env, jobject obj)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  struct voms odata;
  jobject v;

  bool res = vd->DefaultData(odata);

  if (res)
    v = returnVomsPeer(env, odata);
  else
    v = NULL;

  jstring str = (jstring)env->GetObjectField(v, vp_user);
  fprintf(stderr, "from DefaulDataReal: ");
  printString(env, str);
  return v;
}

JNIEXPORT jstring JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_ErrorMessage(JNIEnv *env, jobject obj)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  return returnString(env, vd->ErrorMessage());
}

JNIEXPORT jint JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_ErrorCode(JNIEnv *env, jobject obj)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  return vd->error;
}

JNIEXPORT void JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_destroy(JNIEnv *env, jobject obj)
{
  jlong sl   = env->GetLongField(obj, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  delete vd;
}

JNIEXPORT void JNICALL
Java_org_glite_security_voms_peers_VomsdataPeer_initializer(JNIEnv *env, jclass cls)
{
  jclass tmp;

  vd_fid_d      = env->GetFieldID(cls, "d", "J");
  fprintf(stderr, "got d\n");
  vd_fid_data   = env->GetFieldID(cls, "data", "[Lorg/glite/security/voms/peers/VomsPeer;");
  fprintf(stderr, "got data\n");

  tmp           = env->FindClass("Ljava/lang/String;");
  s_class       = (jclass)env->NewGlobalRef(tmp);
  fprintf(stderr, "got String\n");

  tmp            = env->FindClass("Lorg/glite/security/voms/peers/ContactDataPeer;");
  dp_class       = (jclass)env->NewGlobalRef(tmp);
  fprintf(stderr, "got ContactDataPeer\n");

  tmp             = env->FindClass("Lorg/glite/security/voms/peers/DataPeer;");
  cdp_class       = (jclass)env->NewGlobalRef(tmp);
  fprintf(stderr, "got DataPeer\n");

  tmp            = env->FindClass("Lorg/glite/security/voms/peers/VomsPeer;");
  vp_class       = (jclass)env->NewGlobalRef(tmp);
  fprintf(stderr, "got VomsPeer\n");

  s_constructor = env->GetMethodID(cls, "<init>", "()V");

  fprintf(stderr, "got constructor (exiting)\n");
}

JNIEXPORT jlong JNICALL 
Java_org_glite_security_voms_peers_VomsdataPeer_create__Ljava_lang_String_2Ljava_lang_String_2(JNIEnv *env, jobject obj, jstring dir1, jstring dir2)
{
  jsize dlen1 = env->GetStringUTFLength(dir1);
  jsize dlen2 = env->GetStringUTFLength(dir2);

  const char *dname1, *dname2;
  dname1 = dname2 = NULL;

  std::string d1, d2;

  if (dlen1 != 0) {
    const char *dname1 = env->GetStringUTFChars(dir1,0);
    d1 = std::string(dname1);
  }

  if (dlen2 != 0) {
    const char *dname1 = env->GetStringUTFChars(dir2,0);
    d2 = std::string(dname1);
  }

  vomsdata *vd = new vomsdata(d1, d2);

  if (dname1)
     env->ReleaseStringUTFChars(dir1, dname1);   

  if (dname2)
     env->ReleaseStringUTFChars(dir2, dname2);   

  return (jlong)vd;
}

JNIEXPORT jlong JNICALL 
Java_org_glite_security_voms_peers_VomsdataPeer_create__Lorg_glite_security_voms_peers_VomsdataPeer_2(JNIEnv *env, jobject obj, jobject orig)
{
  jlong sl   = env->GetLongField(orig, vd_fid_d);
  vomsdata *vd = (vomsdata *)sl;

  vomsdata *vnew = new vomsdata(*vd);

  return (jlong)vnew;
}

JNIEXPORT void JNICALL 
Java_org_glite_security_voms_peers_ContactDataPeer_initializer(JNIEnv *env, jclass cls)
{
  dp_class =  (jclass)env->NewGlobalRef(cls);
  dp_constructor = env->GetMethodID(cls, "<init>", 
                                        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)V");
}

JNIEXPORT void JNICALL
Java_org_glite_security_voms_peers_VomsPeer_initializer(JNIEnv *env, jclass cls)
{
  fprintf(stderr, "cls = %d\n",cls);
  vp_class    = (jclass)env->NewGlobalRef(cls);
  vp_constructor = env->GetMethodID(cls, "<init>", "()V");
  vp_version  = env->GetFieldID(cls, "version", "I");
  vp_siglen   = env->GetFieldID(cls, "siglen", "I");
  vp_sign     = env->GetFieldID(cls, "signature","[B");
  vp_user     = env->GetFieldID(cls, "user", "Ljava/lang/String;");
  vp_userca   = env->GetFieldID(cls, "userca", "Ljava/lang/String;");
  vp_server   = env->GetFieldID(cls, "server", "Ljava/lang/String;");
  vp_serverca = env->GetFieldID(cls, "serverca", "Ljava/lang/String;");
  vp_voname   = env->GetFieldID(cls, "voname", "Ljava/lang/String;");
  vp_date1    = env->GetFieldID(cls, "date1", "Ljava/lang/String;");
  vp_date2    = env->GetFieldID(cls, "date2", "Ljava/lang/String;");
  vp_type     = env->GetFieldID(cls, "type", "I");
  vp_std      = env->GetFieldID(cls, "std", "[Lorg/glite/security/voms/peers/DataPeer;");
  vp_custom   = env->GetFieldID(cls, "custom", "Ljava/lang/String;");
  vp_fqan     = env->GetFieldID(cls, "fqan", "[Ljava/lang/String;");
  vp_serial   = env->GetFieldID(cls, "serial", "Ljava/lang/String;");
  vp_holder   = env->GetFieldID(cls, "holder", "[B");
  vp_issuer   = env->GetFieldID(cls, "issuer", "[B");
  vp_uri      = env->GetFieldID(cls, "uri", "Ljava/lang/String;");
}

JNIEXPORT void JNICALL 
Java_org_glite_security_voms_peers_DataPeer_initializer(JNIEnv *env, jclass cls)
{
  cdp_class = (jclass)env->NewGlobalRef(cls);
  cdp_constructor = env->GetMethodID(cls, "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
}

