/*
	File: fridaHookAndroidSomeApp.js
	Function: crifan's Frida hook some Android app related frida js template demo code
	Author: Crifan Li
	Latest: https://github.com/crifan/FridaHookTemplate/Android/frida/fridaHookAndroidSomeApp.js
	Updated: 20241122
  Usage:
   cd /Users/crifan/dev/dev_root/crifan/github/FridaHookTemplate/Android/frida
   frida -U -f com.app.package -l fridaHookAndroidSomeApp.js
*/

/*******************************************************************************
 * Const & Config
*******************************************************************************/

/*******************************************************************************
 * Global Variable
*******************************************************************************/

/*******************************************************************************
 * Common Util
*******************************************************************************/

// https://github.com/crifan/crifanLib/blob/master/javascript/JsUtil.js
// pure JavaScript utils
class JsUtil {

  constructor() {
    console.log("JsUtil constructor")
  }

  static {
  }

  /*---------- Number(Int) ----------*/

  static intToHexStr(intValue, prefix="0x"){
    var hexStr = prefix + intValue.toString(16)
    return hexStr
  }

  /*---------- Log ----------*/

  // Generate single line log string
  // input: logStr="Called: -[NSURLRequest initWithURL:]"
  // output: "=============================== Called: -[NSURLRequest initWithURL:] ==============================="
  static generateLineStr(logStr, isWithSpace=true, delimiterChar="=", lineWidth=80){
    // console.log("logStr=" + logStr, ", isWithSpace=" + isWithSpace + ", delimiterChar=" + delimiterChar + ", lineWidth=" + lineWidth)
    var lineStr = ""

    var realLogStr = ""
    if (isWithSpace) {
      realLogStr = " " + logStr + " "
    } else {
      realLogStr = logStr
    }

    var realLogStrLen = realLogStr.length
    if ((realLogStrLen % 2) > 0){
      realLogStr += " "
      realLogStrLen = realLogStr.length
    }

    var leftRightPaddingStr = ""
    var paddingLen = lineWidth - realLogStrLen
    if (paddingLen > 0) {
      var leftRightPaddingLen = paddingLen / 2
      leftRightPaddingStr = JsUtil.times(delimiterChar, leftRightPaddingLen)
    }

    lineStr = leftRightPaddingStr + realLogStr + leftRightPaddingStr

    // console.log("lineStr:\n" + lineStr)
    return lineStr
  }

  static logStr(curStr, isWithSpace=true, delimiterChar="=", lineWidth=80){
    // let delimiterStr = "--------------------"
    // console.log(delimiterStr + " " + curStr + " " + delimiterChar)
    var lineStr = JsUtil.generateLineStr(curStr, isWithSpace, delimiterChar, lineWidth)
    console.log(lineStr)
  }


  /*---------- Object: Dict/List/... ----------*/

  // convert Object(dict/list/...) to JSON string
  // function toJsonStr(curObj, singleLine=false, space=2){
  static toJsonStr(curObj, singleLine=false, space=2){
    // console.log("toJsonStr: singleLine=" + singleLine)
    // var jsonStr = JSON.stringify(curObj, null, 2)
    var jsonStr = JSON.stringify(curObj, null, space)
    if(singleLine) {
      // jsonStr = jsonStr.replace(/\\n/g, '')
      jsonStr = jsonStr.replace(/\n/g, '')
    }
    return jsonStr
    // return curObj.toString()
  }

  /*---------- List ----------*/

  // check whether is item inside the list
  // eg: curItem="abc", curList=["abc", "def"] => true
  static isItemInList(curItem, curList){
    // method1:
    return curList.includes(curItem)
    // // method2:
    // return curList.indexOf(curItem) > -1
  }

  /*---------- String ----------*/

  /** Function that count occurrences of a substring in a string;
   * @param {String} string               The string
   * @param {String} subString            The sub string to search for
   * @param {Boolean} [allowOverlapping]  Optional. (Default:false)
   *
   * @author Vitim.us https://gist.github.com/victornpb/7736865
   * @see Unit Test https://jsfiddle.net/Victornpb/5axuh96u/
   * @see https://stackoverflow.com/a/7924240/938822
   */
  static occurrences(string, subString, allowOverlapping) {
    // console.log("string=" + string + ",subString=" + subString + ", allowOverlapping=" + allowOverlapping)
    string += "";
    subString += "";
    if (subString.length <= 0) return (string.length + 1);

    var n = 0,
      pos = 0,
      step = allowOverlapping ? 1 : subString.length;

    while (true) {
      pos = string.indexOf(subString, pos);
      // console.log("pos=" + pos)
      if (pos >= 0) {
        ++n;
        pos += step;
      } else break;
    }

    return n;
  }

  // String multiple
  // eg: str="=", num=5 => "====="
  static times(str, num){
    return new Array(num + 1).join(str)
  }

  // check string is empty or null
  static strIsEmpty(curStr){
    var isNull = null == curStr
    var isEmp = "" === curStr
    return isNull || isEmp
  }

  /*---------- Byte ----------*/

  // byte decimaal to byte hex
  // eg:
  //    8 => 8
  //    -60 => c4
  // function byteDecimalToByteHex(byteDecimal) {
  static byteDecimalToByteHex(byteDecimal) {
    // var digitCount = 6
    var digitCount = 2
    var minusDigitCount = 0 - digitCount
    // return (byteDecimal + Math.pow(16, 6)).toString(16).substr(-6)
    // var hexStr = (byteDecimal + Math.pow(16, 2)).toString(16).substr(-2)
    // return (byteDecimal + Math.pow(16, digitCount)).toString(16).substr(minusDigitCount)
    var hexStr = (byteDecimal + Math.pow(16, digitCount)).toString(16).substr(minusDigitCount)
    // console.log("typeof hexStr=" + (typeof hexStr))
    // console.log("hexStr=" + hexStr)
    var hexValue = parseInt(hexStr, 16)
    // console.log("typeof hexValue=" + (typeof hexValue))
    // console.log("hexValue=" + hexValue)
    return hexValue
  }

  /*---------- Object ----------*/

  // check is js string
  static isJsStr(curObj){
    // console.log("curObj=" + curObj)
    var curObjType = (typeof curObj)
    // console.log("curObjType=" + curObjType)
    var isStr = curObjType === "string"
    // console.log("isStr=" + isStr)
    return isStr
  }

  /*---------- Pointer ----------*/

  // check pointer is valid or not
  // example
  // 		0x103e79560 => true
  // 		0xc => false
  static isValidPointer(curPtr){
    let MinValidPointer = 0x10000
    var isValid = curPtr > MinValidPointer
    // console.log("curPtr=" + curPtr, " -> isValid=" + isValid)
    return isValid
  }

}

// https://github.com/crifan/crifanLib/blob/master/javascript/frida/FridaUtil.js
// Frida Common Util
class FridaUtil {

  constructor() {
    console.log("FridaUtil constructor")
    console.log("FridaUtil Process.platform=" + Process.platform)
  }

  static isiOS(){
    var platform = Process.platform
    // console.log("platform=" + platform)
    var isJavaAvailable = Java.available
    // console.log("isJavaAvailable=" + isJavaAvailable)
    var isDarwin = platform === "darwin"
    // console.log("isDarwin=" + isDarwin)
    var isiOSOS = (!isJavaAvailable) && isDarwin
    // console.log("isiOSOS=" + isiOSOS)
    return isiOSOS
  }

  static isAndroid(){
    var platform = Process.platform
    // console.log("platform=" + platform)
    var isJavaAvailable = Java.available
    // console.log("isJavaAvailable=" + isJavaAvailable)
    var isLinux = platform === "linux"
    // console.log("isLinux=" + isLinux)
    var isAndroidOS = isJavaAvailable && isLinux
    // console.log("isAndroidOS=" + isAndroidOS)
    return isAndroidOS
  }

  // Frida pointer to UTF-8 string
  static ptrToUtf8Str(curPtr){
    var curUtf8Str = curPtr.readUtf8String()
    // console.log("curUtf8Str=" + curUtf8Str)
    return curUtf8Str
  }

  // Frida pointer to C string
  static ptrToCStr(curPtr){
    // var curCStr = Memory.readCString(curPtr)
    var curCStr = curPtr.readCString()
    // var curCStr = curPtr.readUtf8String()
    // console.log("curCStr=" + curCStr)
    return curCStr
  }

  // print function call and stack, output content type is: address
  static printFunctionCallStack_addr(curContext, prefix=""){
    var backtracerType = Backtracer.ACCURATE
    // var backtracerType = Backtracer.FUZZY
    if (!JsUtil.strIsEmpty(prefix)){
      prefix = prefix + " "
    }
    // const linePrefix = "\n"
    // const linePrefix = "\n\t"
    const linePrefix = "\n  "
    // const linePrefix = "\n "
    // const linePrefix = "\n"
    console.log(prefix + 'Stack:' + linePrefix +
      Thread.backtrace(curContext, backtracerType)
      .map(DebugSymbol.fromAddress).join(linePrefix) + '\n');
  }

  static dumpMemory(toDumpPtr, byteLen=128){
    var buf = toDumpPtr.readByteArray(byteLen)
    var dumpHexStr = hexdump(
      buf,
      {
        offset: 0,
        length: byteLen,
        header: true,
        ansi: true
      }
    )
    console.log("dumpHexStr=\n" + dumpHexStr)
  }

  // Frida Stalker hoo unknown name native function
  static stalkerHookUnnameNative(moduleBaseAddress, funcRelativeStartAddr, functionSize, argNum, hookFuncMap){
    console.log("Frida Stalker hook: module: baseAddress=" + moduleBaseAddress)

    var functionSizeHexStr = JsUtil.intToHexStr(functionSize)
    var funcRelativeStartAddrHexStr = JsUtil.intToHexStr(funcRelativeStartAddr)
    var funcRelativeEndAddr = funcRelativeStartAddr + functionSize
    var funcRelativeEndAddrHexStr = JsUtil.intToHexStr(funcRelativeEndAddr)
    console.log("function: relativeStartAddr=" + funcRelativeStartAddrHexStr + ", size=" + functionSize + "=" + functionSizeHexStr + ", relativeEndAddr=" + funcRelativeEndAddrHexStr)

    const funcRealStartAddr = moduleBaseAddress.add(funcRelativeStartAddr)
    // var funcRealEndAddr = funcRealStartAddr + functionSize
    const funcRealEndAddr = funcRealStartAddr.add(functionSize)
    console.log("funcRealStartAddr=" + funcRealStartAddr + ", funcRealEndAddr=" + funcRealEndAddr)
    var curTid = null
    console.log("curTid=" + curTid)
    Interceptor.attach(funcRealStartAddr, {
      onEnter: function(args) {
        JsUtil.logStr("Trigged addr: relative [" + funcRelativeStartAddrHexStr + "] = real [" + funcRealStartAddr + "]")

        for(var i = 0; i < argNum; i++) {
          var curArg = args[i]
          console.log("arg[" + i  + "]=" + curArg)
        }

        var curTid = Process.getCurrentThreadId()
        console.log("curTid=" + curTid)
        Stalker.follow(curTid, {
            events: {
              call: false, // CALL instructions: yes please            
              ret: true, // RET instructions
              exec: false, // all instructions: not recommended as it's
              block: false, // block executed: coarse execution trace
              compile: false // block compiled: useful for coverage
            },
            // onReceive: Called with `events` containing a binary blob comprised of one or more GumEvent structs. See `gumevent.h` for details about the format. Use `Stalker.parse()` to examine the data.
            onReceive(events) {
              var parsedEvents = Stalker.parse(events)
              // var parsedEventsStr = JSON.stringify(parsedEventsStr)
              // console.log(">>> into onReceive: parsedEvents=" + parsedEvents + ", parsedEventsStr=" + parsedEventsStr);
              console.log(">>> into onReceive: parsedEvents=" + parsedEvents);
            },

            // transform: (iterator: StalkerArm64Iterator) => {
            transform: function (iterator) {
              // https://www.radare.org/doc/frida/interfaces/StalkerArmIterator.html

              // console.log("iterator=" + iterator)
              var instruction = iterator.next()
              const startAddress = instruction.address
              // console.log("+++ into iterator: startAddress=" + startAddress)
              // const isAppCode = startAddress.compare(funcRealStartAddr) >= 0 && startAddress.compare(funcRealEndAddr) === -1
              // const isAppCode = (startAddress.compare(funcRealStartAddr) >= 0) && (startAddress.compare(funcRealEndAddr) < 0)
              const gt_realStartAddr = startAddress.compare(funcRealStartAddr) >= 0
              const lt_realEndAddr = startAddress.compare(funcRealEndAddr) < 0
              var isAppCode = gt_realStartAddr && lt_realEndAddr
              console.log("+++ into iterator: startAddress=" + startAddress + ", isAppCode=" + isAppCode)

              // // for debug
              // isAppCode = true

              // console.log("isAppCode=" + isAppCode + ", gt_realStartAddr=" + gt_realStartAddr + ", lt_realEndAddr=" + lt_realEndAddr)
              do {
                if (isAppCode) {
                  // is origal function code = which we focus on

                  // console.log("instruction: address=" + instruction.address
                  //     + ",next=" + instruction.next()
                  //     + ",size=" + instruction.size
                  //     + ",mnemonic=" + instruction.mnemonic
                  //     + ",opStr=" + instruction.opStr
                  //     + ",operands=" + JSON.stringify(instruction.operands)
                  //     + ",regsAccessed=" + JSON.stringify(instruction.regsAccessed)
                  //     + ",regsRead=" + JSON.stringify(instruction.regsRead)
                  //     + ",regsWritten=" + JSON.stringify(instruction.regsWritten)
                  //     + ",groups=" + JSON.stringify(instruction.groups)
                  //     + ",toString()=" + instruction.toString()
                  //     + ",toJSON()=" + instruction.toJSON()
                  // );

                  var curRealAddr = instruction.address
                  // console.log("curRealAddr=" + curRealAddr)
                  // const isAppCode = curRealAddr.compare(funcRealStartAddr) >= 0 && curRealAddr.compare(funcRealEndAddr) === -1
                  // console.log(curRealAddr + ": isAppCode=" + isAppCode)
                  var curOffsetHexPtr = curRealAddr.sub(funcRealStartAddr)
                  var curOffsetInt = curOffsetHexPtr.toInt32()
                  console.log("current: realAddr=" + curRealAddr + " -> offset: hex=" + curOffsetHexPtr + "=" + curOffsetInt)

                  // var instructionStr = instruction.mnemonic + " " + instruction.opStr
                  var instructionStr = instruction.toString()
                  // console.log("\t" + curRealAddr + ": " + instructionStr);
                  // console.log("\t" + curRealAddr + " <+" + curOffsetHexPtr + ">: " + instructionStr)
                  console.log("\t" + curRealAddr + " <+" + curOffsetInt + ">: " + instructionStr)

                  if (curOffsetInt in hookFuncMap){
                    console.log("offset: " + curOffsetHexPtr + "=" + curOffsetInt)
                    // let curHookFunc = hookFuncMap.get(curOffsetInt)
                    var curHookFunc = hookFuncMap[curOffsetInt]
                    // console.log("curOffsetInt=" + curOffsetInt + " -> curHookFunc=" + curHookFunc)

                    // putCallout -> https://www.radare.org/doc/frida/interfaces/StalkerArmIterator.html#putCallout
                    // StalkerScriptCallout -> https://www.radare.org/doc/frida/types/StalkerScriptCallout.html
                    // CpuContext -> https://www.radare.org/doc/frida/types/CpuContext.html
                    // Arm64CpuContext -> https://www.radare.org/doc/frida/interfaces/Arm64CpuContext.html

                    // work: normal
                    iterator.putCallout(curHookFunc)

                    // var extraDataDict = {
                    //   "curOffsetInt": curOffsetInt
                    // }
                    // Not work: abnormal
                    // iterator.putCallout((context) => {
                    // // iterator.putCallout((context, extraDataDict) => {
                    //   // console.log("match offset: " + curOffsetHexPtr + ", curRealAddr=" + curRealAddr)
                    //   // curHookFunc(context, curOffsetInt, moduleBaseAddress)
                    //   // context.curOffsetInt = curOffsetInt
                    //   // context.curOffsetHexPtr = curOffsetHexPtr
                    //   // context.moduleBaseAddress = moduleBaseAddress
                    //   // context[curOffsetInt] = curOffsetInt
                    //   // context[curOffsetHexPtr] = curOffsetHexPtr
                    //   // context[moduleBaseAddress] = moduleBaseAddress
                    //   // curHookFunc(context, extraDataDict)
                    //   curHookFunc(context)
                    // })
                  }

                }
                iterator.keep()
              } while ((instruction = iterator.next()) !== null)
            }
        });

        // function needDebug(context) {
        //     console.log("into needDebug")
        //     // console.log("into needDebug: context=" + context)
        //     // var contextStr = JSON.stringify(context, null, 2)
        //     // console.log("context=" + contextStr)
        //     // var x9Value1 = context.x9
        //     // var x9Value2 = context["x9"]
        //     // console.log("x9Value1=" + x9Value1 + ", x9Value2=" + x9Value2)
        // }
      },
      onLeave: function(retval) {
        console.log("addr: relative [" + funcRelativeStartAddrHexStr + "] real [" + funcRealStartAddr + "] -> retval=" + retval)
        if (curTid != null) {
          Stalker.unfollow(curTid)
          console.log("Stalker.unfollow curTid=", curTid)
        }
      }
    })
  }


}

// https://github.com/crifan/crifanLib/blob/master/javascript/frida/FridaAndroidUtil.js
// Frida Android Util
class FridaAndroidUtil {

  // android common root related binary files
  // static RootBinFileList = ["/system/bin/su", "/system/xbin/su", "/system/bin/magisk"]
  static RootBinFileList = [
    "/su",
    "/su/bin/su",
    "/sbin/su",
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "/data/local/su",
    "/system/xbin/su",
    "/system/bin/su",
    "/system/bin/magisk",
    "/system/sd/xbin/su",
    "/system/bin/failsafe/su",
    "/system/bin/cufsdosck",
    "/system/xbin/cufsdosck",
    "/system/bin/cufsmgr",
    "/system/xbin/cufsmgr",
    "/system/bin/cufaevdd",
    "/system/xbin/cufaevdd",
    "/system/bin/conbb",
    "/system/xbin/conbb",
  ]

  // {env: {clazz: className} }
  static cacheDictEnvClazz = {}

  static curThrowableCls = null

  static JavaArray = null
  static JavaArrays = null
  static JavaArrayList = null

  static JavaByteArr = null
  static JavaObjArr = null

  constructor() {
    console.log("FridaAndroidUtil constructor")
  }

  static {
    if (FridaUtil.isAndroid()) {
      FridaAndroidUtil.curThrowableCls = Java.use("java.lang.Throwable")
      console.log("FridaAndroidUtil.curThrowableCls=" + FridaAndroidUtil.curThrowableCls)

      console.log("FridaAndroidUtil.cacheDictEnvClazz=" + FridaAndroidUtil.cacheDictEnvClazz)
  
      FridaAndroidUtil.JavaArray = Java.use('java.lang.reflect.Array')
      console.log("FridaAndroidUtil.JavaArray=" + FridaAndroidUtil.JavaArray)
      FridaAndroidUtil.JavaArrays = Java.use("java.util.Arrays")
      console.log("FridaAndroidUtil.JavaArrays=" + FridaAndroidUtil.JavaArrays)
      FridaAndroidUtil.JavaArrayList = Java.use('java.util.ArrayList')
      console.log("FridaAndroidUtil.JavaArrayList=" + FridaAndroidUtil.JavaArrayList)
  
      FridaAndroidUtil.JavaByteArr = Java.use("[B")
      console.log("FridaAndroidUtil.JavaByteArr=" + FridaAndroidUtil.JavaByteArr)
      // var JavaObjArr = Java.use("[Ljava.lang.Object")
      FridaAndroidUtil.JavaObjArr = Java.use("[Ljava.lang.Object;")
      console.log("FridaAndroidUtil.JavaObjArr=" + FridaAndroidUtil.JavaObjArr)  
    } else {
      console.warn("FridaAndroidUtil: Non Android platfrom, no need init Android related")
    }
  }

  static printModuleInfo(moduleName){
    const foundModule = Module.load(moduleName)
    // const foundModule = Module.ensureInitialized()
    console.log("foundModule=" + foundModule)
  
    if (null == foundModule) {
      return
    }
  
    console.log("Module: name=" + foundModule.name + ", base=" + foundModule.base + ", size" + foundModule.size + ", path=" + foundModule.path)
  
    var curSymbolList = foundModule.enumerateSymbols()
    console.log("Symbol: length=" + curSymbolList.length + ", list=" + curSymbolList)
    for(var i = 0; i < curSymbolList.length; i++) {
      console.log("---------- Symbol [" + i + "]----------")
      var curSymbol = curSymbolList[i]
      var sectionStr = JSON.stringify(curSymbol.section)
      console.log("name=" + curSymbol.name + ", address=" + curSymbol.address + "isGlobal=" + curSymbol.isGlobal + ", type=" + curSymbol.type + ", section=" + sectionStr)
    }
  
    var curExportList = foundModule.enumerateExports()
    console.log("Export: length=" + curExportList.length + ", list=" + curExportList)
    for(var i = 0; i < curExportList.length; i++) {
      console.log("---------- Export [" + i + "]----------")
      var curExport = curExportList[i]
      console.log("type=" + curExport.type + ", name=" + curExport.name + ", address=" + curExport.address)
    }
  }

  static waitForLibLoading(libraryName, callback_afterLibLoaded=null){
    console.log("libraryName=" + libraryName + ", callback_afterLibLoaded=" + callback_afterLibLoaded)
    // var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext")
    var android_dlopen_ext = Module.getExportByName(null, "android_dlopen_ext")
    console.log("android_dlopen_ext=" + android_dlopen_ext)
    if (null == android_dlopen_ext) {
      return
    }
  
    Interceptor.attach(android_dlopen_ext, {
      onEnter: function (args) {
        // android_dlopen_ext(const char *_Nullable __filename, int __flags, const android_dlextinfo *_Nullable __info)	

        // console.log("args=" + args)
        var filenamePtr = args[0]
        var libFullPath = FridaUtil.ptrToCStr(filenamePtr)
        // console.log("libFullPath=" + libFullPath)
        var flags = args[1]
        var info = args[2]
        // console.log("android_dlopen_ext: [+] libFullPath=" + libFullPath + ", flags=" + flags + ", info=" + info)
        // if(libraryName === libFullPath){
        if(libFullPath.includes(libraryName)){
          console.log("+++ Loaded lib " + libraryName + ", flags=" + flags + ", info=" + info)
          this.isLibLoaded = true

          this._libFullPath = libFullPath
        }
      },
  
      onLeave: function () {
        if (this.isLibLoaded) {
          this.isLibLoaded = false
  
          if(null != callback_afterLibLoaded) {
            // callback_afterLibLoaded(libraryName)
            callback_afterLibLoaded(this._libFullPath)
          }
        }
      }
    })
  
  }

  static hookAfterLibLoaded(libName, callback_afterLibLoaded=null){
    console.log("libName=" + libName)
    FridaAndroidUtil.waitForLibLoading(libName, callback_afterLibLoaded)
  }

  static findSymbolFromLib(soLibName, jniFuncName, callback_isFound) {
    console.log("soLibName=" + soLibName + ", jniFuncName=" + jniFuncName + ", callback_isFound=" + callback_isFound)
  
    var foundSymbolList = []
    let libSymbolList = Module.enumerateSymbolsSync(soLibName)
    // console.log("libSymbolList=" + libSymbolList)
    for (let i = 0; i < libSymbolList.length; i++) {
        var curSymbol = libSymbolList[i]
        // console.log("[" + i  + "] curSymbol=" + curSymbol)
  
        var symbolName = curSymbol.name
        // console.log("[" + i  + "] symbolName=" + symbolName)

        // var isFound = callback_isFound(symbolName)
        var isFound = callback_isFound(curSymbol, jniFuncName)
        // console.log("isFound=" + isFound)
  
        if (isFound) {
          var symbolAddr = curSymbol.address
          // console.log("symbolAddr=" + symbolAddr)

          foundSymbolList.push(curSymbol)
          console.log("+++ Found [" + i + "] symbol: addr=" + symbolAddr + ", name=" + symbolName)
        }
    }
  
    // console.log("foundSymbolList=" + foundSymbolList)
    return foundSymbolList
  }

  static findFunction_libart_so(jniFuncName, func_isFound) {
    var foundSymbolList = FridaAndroidUtil.findSymbolFromLib("libart.so", jniFuncName, func_isFound)
    console.log("foundSymbolList=" + foundSymbolList)
    return foundSymbolList
  }

  static isFoundSymbol(curSymbol, symbolName){
    // return symbolName.includes("NewStringUTF")
    // return symbolName.includes("CheckJNI12NewStringUTF")
    // return symbol.name.includes("CheckJNI12NewStringUTF")

    // _ZN3art12_GLOBAL__N_18CheckJNI12NewStringUTFEP7_JNIEnvPKc.llvm.16005601603641821307
    // _ZN3art3JNIILb0EE12NewStringUTFEP7_JNIEnvPKc
    // _ZN3art2gc4Heap24AllocObjectWithAllocatorILb1ELb1ENS_12_GLOBAL__N_119NewStringUTFVisitorEEEPNS_6mirror6ObjectEPNS_6ThreadENS_6ObjPtrINS5_5ClassEEEmNS0_13AllocatorTypeERKT1_
    // _ZNK3art12_GLOBAL__N_119NewStringUTFVisitorclENS_6ObjPtrINS_6mirror6ObjectEEEm
    // _ZN3art2gc4Heap16AllocLargeObjectILb1ENS_12_GLOBAL__N_119NewStringUTFVisitorEEEPNS_6mirror6ObjectEPNS_6ThreadEPNS_6ObjPtrINS5_5ClassEEEmRKT0_
    // _ZZN3art2gc4Heap24AllocObjectWithAllocatorILb1ELb0ENS_12_GLOBAL__N_119NewStringUTFVisitorEEEPNS_6mirror6ObjectEPNS_6ThreadENS_6ObjPtrINS5_5ClassEEEmNS0_13AllocatorTypeERKT1_ENKUlvE_clEv
    // _ZN3art3JNIILb1EE12NewStringUTFEP7_JNIEnvPKc
    // _ZZN3art3JNIILb0EE12NewStringUTFEP7_JNIEnvPKcE19prev_bad_input_time
    // _ZZN3art3JNIILb1EE12NewStringUTFEP7_JNIEnvPKcE19prev_bad_input_time
    // return symbol.name.includes("NewStringUTF")

    // symbolName.includes("RegisterNatives") && symbolName.includes("CheckJNI")
    // return symbolName.includes("CheckJNI15RegisterNatives")
    // return symbolName.includes("RegisterNatives")

    // _ZN3art12_GLOBAL__N_18CheckJNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi.llvm.16005601603641821307
    // _ZN3art3JNIILb0EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
    // _ZN3art3JNIILb1EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
    // return symbol.name.includes("RegisterNatives")

    // return symbolName.includes("CheckJNI11GetMethodID")
    // return symbolName.includes("GetMethodID")

    // _ZN3art12_GLOBAL__N_18CheckJNI19GetMethodIDInternalEPKcP7_JNIEnvP7_jclassS3_S3_b
    // _ZN3art12_GLOBAL__N_18CheckJNI11GetMethodIDEP7_JNIEnvP7_jclassPKcS7_.llvm.16005601603641821307
    // _ZN3art3JNIILb0EE11GetMethodIDEP7_JNIEnvP7_jclassPKcS7_
    // _ZN3art3JNIILb1EE11GetMethodIDEP7_JNIEnvP7_jclassPKcS7_
    // return symbol.name.includes("GetMethodID")

    return curSymbol.name.includes(symbolName)
  }

  static findJniFunc(jniFuncName){
    var jniSymbolList = FridaAndroidUtil.findFunction_libart_so(jniFuncName, FridaAndroidUtil.isFoundSymbol)
    return jniSymbolList
  }

  static doHookJniFunc_multipleMatch(foundSymbolList, callback_onEnter, callback_onLeave=null){
    if (null == foundSymbolList){
      return
    }

    var symbolNum = foundSymbolList.length
    console.log("symbolNum=" + symbolNum)
    if (symbolNum == 0){
      return
    }

    for(var i = 0; i < symbolNum; ++i) {
      var eachSymbol = foundSymbolList[i]
      // console.log("eachSymbol=" + eachSymbol)
      var curSymbolAddr = eachSymbol.address
      console.log("curSymbolAddr=" + curSymbolAddr)

      Interceptor.attach(curSymbolAddr, {
        onEnter: function (args) {
          callback_onEnter(this, eachSymbol, args)
        },
        onLeave: function(retVal){
          if (null != callback_onLeave) {
            callback_onLeave(this, retVal)
          }
        }
      })
    }
  }

  static hookJniFunc(jniFuncName, hookFunc_onEnter, hookFunc_onLeave=null){
    var jniSymbolList = FridaAndroidUtil.findJniFunc(jniFuncName)
    FridaAndroidUtil.doHookJniFunc_multipleMatch(jniSymbolList, hookFunc_onEnter, hookFunc_onLeave)
  }

  static hookNative_NewStringUTF(){
    FridaAndroidUtil.hookJniFunc(
      "NewStringUTF",
      function(thiz, curSymbol, args){
        JsUtil.logStr("Trigged NewStringUTF [" + curSymbol.address + "]")
          // jstring NewStringUTF(JNIEnv *env, const char *bytes);
          var jniEnv = args[0]
          console.log("jniEnv=" + jniEnv)

          var newStrPtr = args[1]
          // var newStr = newStrPtr.readCString()
          // var newStr = FridaUtil.ptrToUtf8Str(newStrPtr)
          var newStr = FridaUtil.ptrToCStr(newStrPtr)
          console.log("newStrPtr=" + newStrPtr + " -> newStr=" + newStr)
      }
    )
  }

  static hookNative_GetMethodID(callback_enableLog=null){
    FridaAndroidUtil.hookJniFunc(
      "GetMethodID", 
      function(thiz, curSymbol, args){
        var curSymbolAddr = curSymbol.address

        // jmethodID GetMethodID(JNIEnv *env, jclass clazz, const char *name, const char *sig);
        var jniEnv = args[0]

        var clazz = args[1]
        var jclassName = FridaAndroidUtil.getJclassName(clazz)

        var namePtr = args[2]
        var nameStr = FridaUtil.ptrToUtf8Str(namePtr)
        
        var sigPtr = args[3]
        var sigStr = FridaUtil.ptrToUtf8Str(sigPtr)

        thiz.enableLog = false
        if (callback_enableLog) {
          thiz.enableLog = callback_enableLog(jniEnv, jclassName, nameStr, sigStr)
        } else {
          thiz.enableLog = true          
        }

        if (thiz.enableLog) {
          JsUtil.logStr("Trigged GetMethodID [" + curSymbolAddr + "]")

          console.log("jniEnv=" + jniEnv)
          console.log("clazz=" + clazz + " -> jclassName=" + jclassName)
          console.log("namePtr=" + namePtr + " -> nameStr=" + nameStr)
          console.log("sigPtr=" + sigPtr + " -> sigStr=" + sigStr)

          // if ("com.bytedance.mobsec.metasec.ml.MS" == jclassName){
          //   console.log("curSymbolAddr=" + curSymbolAddr)
          //   var libArtFuncPtr_GetMethodID = curSymbolAddr
          //   console.log("libArtFuncPtr_GetMethodID=" + libArtFuncPtr_GetMethodID)
          //   // jmethodID GetMethodID(JNIEnv *env, jclass clazz, const char *name, const char *sig);
          //   var nativeFunc_GetMethodID = new NativeFunction(
          //     libArtFuncPtr_GetMethodID,
          //     // 'jmethodID',
          //     // 'int',
          //     'pointer',
          //     // ['pointer', 'jclass', 'pointer', 'pointer']
          //     // ['pointer', 'int', 'pointer', 'pointer']
          //     ['pointer', 'pointer', 'pointer', 'pointer']
          //     // ['JNIEnv*', 'jclass', 'char*', 'char*']
          //   )
          //   console.log("nativeFunc_GetMethodID=" + nativeFunc_GetMethodID)
          //   // console.log("jniEnv=" + jniEnv + ", clazz=" + clazz + " -> jclassName=" + jclassName)
          //   // var funcName_Bill = "Bill"
          //   // var funcSig_Bill = "()V"
          //   var funcSig_common = Memory.allocUtf8String("()V")
          //   console.log("funcSig_common=" + funcSig_common)

          //   var funcName_Bill = Memory.allocUtf8String("Bill")
          //   console.log("funcName_Bill=" + funcName_Bill)
          //   var jMethodID_Bill = nativeFunc_GetMethodID(jniEnv, clazz, funcName_Bill, funcSig_common)
          //   console.log("jMethodID_Bill=" + jMethodID_Bill)

          //   var funcName_Louis = Memory.allocUtf8String("Louis")
          //   console.log("funcName_Louis=" + funcName_Louis)
          //   var jMethodID_Louis = nativeFunc_GetMethodID(jniEnv, clazz, funcName_Louis, funcSig_common)
          //   console.log("jMethodID_Louis=" + jMethodID_Louis)

          //   var funcName_Zeoy = Memory.allocUtf8String("Zeoy")
          //   console.log("funcName_Zeoy=" + funcName_Zeoy)
          //   var jMethodID_Zeoy = nativeFunc_GetMethodID(jniEnv, clazz, funcName_Zeoy, funcSig_common)
          //   console.log("jMethodID_Zeoy=" + jMethodID_Zeoy)

          //   var funcName_Francies = Memory.allocUtf8String("Francies")
          //   console.log("funcName_Francies=" + funcName_Francies)
          //   var jMethodID_Francies = nativeFunc_GetMethodID(jniEnv, clazz, funcName_Francies, funcSig_common)
          //   console.log("jMethodID_Francies=" + jMethodID_Francies)
          // }

        }
      },
      function(thiz, retVal){
        if (thiz.enableLog) {
          console.log("GetMethodID retVal=" + retVal)
        }
      }
    )
  }

  /* print detail of JNINativeMethod:

    typedef struct {
      const char* name;
      const char* signature;
      void* fnPtr;
    } JNINativeMethod;
  */
  static printJNINativeMethodDetail(methodsPtr, methodNum){
    // console.log("methodsPtr=" + methodsPtr + ", methodNum=" + methodNum)

    // console.log("Process.pointerSize=" + Process.pointerSize) // 8
    let JNINativeMethod_size = Process.pointerSize * 3
    // console.log("JNINativeMethod_size=" + JNINativeMethod_size) // 24

    for (var i = 0; i < methodNum; i++) {
      JsUtil.logStr("method [" + i + "]", true, "-", 80)

      var curPtrStartPos = i * JNINativeMethod_size
      // console.log("curPtrStartPos=" + curPtrStartPos)

      var namePtrPos = methodsPtr.add(curPtrStartPos)
      // console.log("namePtrPos=" + namePtrPos)
      var namePtr = Memory.readPointer(namePtrPos)
      // console.log("namePtr=" + namePtr)
      // var nameStr = Memory.readCString(namePtr)
      var nameStr = FridaUtil.ptrToCStr(namePtr)
      // console.log("nameStr=" + nameStr)
      console.log("name: pos=" + namePtrPos + " -> ptr=" + namePtr + " -> str=" + nameStr)

      var sigPtrPos = methodsPtr.add(curPtrStartPos + Process.pointerSize)
      // var sigPtrPos = namePtrPos.add(Process.pointerSize)
      // console.log("sigPtrPos=" + sigPtrPos)
      var sigPtr = Memory.readPointer(sigPtrPos)
      // console.log("sigPtr=" + sigPtr)
      var sigStr = FridaUtil.ptrToCStr(sigPtr)
      // console.log("sigStr=" + sigStr)
      console.log("signature: pos=" + sigPtrPos + " -> ptr=" + sigPtr + " -> str=" + sigStr)

      var fnPtrPos = methodsPtr.add(curPtrStartPos + Process.pointerSize*2)
      // var fnPtrPos = sigPtrPos.add(Process.pointerSize)
      // console.log("fnPtrPos=" + fnPtrPos)
      var fnPtrPtr = Memory.readPointer(fnPtrPos)
      // console.log("fnPtrPtr=" + fnPtrPtr)
      var foundModule = Process.findModuleByAddress(fnPtrPtr)
      // console.log("foundModule=" + foundModule)
      var moduleBase = foundModule.base
      // console.log("moduleBase=" + moduleBase)
      var offsetInModule = ptr(fnPtrPtr).sub(moduleBase)
      // console.log("offsetInModule=" + offsetInModule)
      console.log("fnPtr: pos=" + fnPtrPos + " -> ptr=" + fnPtrPtr + " -> offset=" + offsetInModule)

      console.log("Module: name=" + foundModule.name + ", base=" + foundModule.base + ", size=" + foundModule.size_ptr + ", path=" + foundModule.path)
    }
  }

  static hookNative_RegisterNatives(){
    // var symbolList_RegisterNatives = find_RegisterNatives()
    // hoook_RegisterNatives(symbolList_RegisterNatives)

    FridaAndroidUtil.hookJniFunc(
      "RegisterNatives",
      function(thiz, curSymbol, args){
        JsUtil.logStr("Trigged RegisterNatives [" + curSymbol.address + "]")

        // jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);
        var jniEnv = args[0]
        console.log("jniEnv=" + jniEnv)

        var clazz = args[1]
        var jclassName = FridaAndroidUtil.getJclassName(clazz)
        console.log("clazz=" + clazz + " -> jclassName=" + jclassName)

        var methodsPtr = args[2]
        console.log("methodsPtr=" + methodsPtr)

        var nMethods = args[3]
        var methodNum = parseInt(nMethods)
        console.log("nMethods=" + nMethods + " -> methodNum=" + methodNum)

        FridaAndroidUtil.printJNINativeMethodDetail(methodsPtr, methodNum)
      }
  )

  }

  // java byte array to js byte array
  static javaByteArrToJsByteArr(javaByteArr){
    // var javaByteArrLen = javaByteArr.length
    // console.log("javaByteArrLen=" + javaByteArrLen) // javaByteArrLen=undefined
    var javaByteArrGotLen = FridaAndroidUtil.JavaArray.getLength(javaByteArr)
    console.log("javaByteArrGotLen=" + javaByteArrGotLen) // javaByteArrGotLen=8498
    var jsByteArr = new Array()
    // console.log("jsByteArr=" + jsByteArr)
    for(var i = 0; i < javaByteArrGotLen; ++i) {
      // jsByteArr[i] = javaByteArr[i]
      var curByte = FridaAndroidUtil.JavaArray.get(javaByteArr, i)
      // console.log("curByte=" + curByte)
      jsByteArr[i] = curByte
    }
    // console.log("jsByteArr=" + jsByteArr)
    return jsByteArr
  }

  // java array/list (byte array / List<Integer> )to string
  static javaArrayListToStr(javaArraryList){
    var jsArrayList = FridaAndroidUtil.javaByteArrToJsByteArr(javaArraryList)
    console.log("jsArrayList=" + jsArrayList)
    var jsArrayListStr = jsArrayList.toString()
    console.log("jsArrayListStr=" + jsArrayListStr)
    return jsArrayListStr
  }

  // get java class name from clazz
  // example:
  //  clazz=0x35 -> className=java.lang.ref.Reference
  //  clazz=0xa1 -> className=com.tencent.wcdb.database.SQLiteConnection
  //  clazz=0x91 -> className=java.lang.String
  //  clazz=0x42a6 -> jclassName=java.lang.Integer
  // static getJclassName(clazz){
  // Note: if not use cache, some time will cause Frida crashed: Process terminated
  static getJclassName(clazz, isUseCache=true){
  // static getJclassName(clazz, isUseCache=false){
    // console.log("clazz=" + clazz)
    var isFoundCache = false
    var isNeedAddToCache = false
    var className = ""

    if (null == clazz){
      return className
    }

    var env = Java.vm.tryGetEnv()
    // console.log("env=" + env) // env=[object Object]
    if (null == env){
      return className
    }

    // console.log("isUseCache=" + isUseCache)
    if(isUseCache){
      if (env in FridaAndroidUtil.cacheDictEnvClazz){
        var cachedClazzClassnameDict = FridaAndroidUtil.cacheDictEnvClazz[env]
        if (clazz in cachedClazzClassnameDict) {
          className = cachedClazzClassnameDict[clazz]
          if (JsUtil.strIsEmpty(className)){
            console.warn("clazz=" + clazz + " in cache=" + cachedClazzClassnameDict + ", but empty className")
          } else {
            isFoundCache = true
          }
        }
        else {
          // console.log("clazz=" + clazz + " not in cache=" + cachedClazzClassnameDict)
        }
      }
      else {
        // console.log("env=" + env + " not in cache=" + FridaAndroidUtil.cacheDictEnvClazz)
      }
    }

    // console.log("isFoundCache=" + isFoundCache)
    if (!isFoundCache){
      // var clazzInt = clazz.toInt32(clazzInt)
      // // console.log("clazzInt=" + clazzInt)
      // const ProbablyErrorMinClazzValue = 0x1000
      // var isProbabllyError = clazzInt < ProbablyErrorMinClazzValue
      // if (isProbabllyError) {
      //   // console.warn("Not do getClassName, for probably erro for clazz=" + clazz + ", less then ProbablyErrorMinClazzValue=" + ProbablyErrorMinClazzValue)
      // } else {
      try {
        className = env.getClassName(clazz)
      } catch(err){
        console.error("getJclassName catch: err=" + err + ", for clazz=" + clazz)
      } finally {
        if (JsUtil.strIsEmpty(className)){
          console.error("getJclassName finally: empty className for clazz=" + clazz)
        } else {
          // console.log("getJclassName OK: clazz=" + clazz + " -> className=" + className)
          if (isUseCache){
            isNeedAddToCache = true
          }
        }
      }
      // }
    }

    if (isUseCache && isNeedAddToCache){  
      if (env in FridaAndroidUtil.cacheDictEnvClazz){
        var oldCachedClazzClassnameDict = FridaAndroidUtil.cacheDictEnvClazz[env]
        // console.log("old CachedClazzClassnameDict=" + oldCachedClazzClassnameDict)
        oldCachedClazzClassnameDict[clazz] = className
        // console.log("new CachedClazzClassnameDict=" + oldCachedClazzClassnameDict)
        FridaAndroidUtil.cacheDictEnvClazz[env] = oldCachedClazzClassnameDict
        // console.log("Added clazz=" + clazz + ", className=" + className + " -> to existed env cache:" + FridaAndroidUtil.cacheDictEnvClazz)
      } else {
        FridaAndroidUtil.cacheDictEnvClazz[env] = {
          clazz: className
        }
        // console.log("Added clazz=" + clazz + ", className=" + className + " -> to cache:" + FridaAndroidUtil.cacheDictEnvClazz)
      }
    }

    var logPrefix = ""
    if (isFoundCache){
      logPrefix = "Cached: "
    }

    // console.log("className=" + className)
    // console.log(logPrefix + "clazz=" + clazz + "-> className=" + className)
    return className
  }

  static getJavaClassName(curObj){
    var javaClsName = null
    if (null != curObj) {
      // javaClsName = curObj.constructor.name
      javaClsName = curObj.$className
      // console.log("javaClsName=" + javaClsName)
      // var objType = (typeof curObj)
      // console.log("objType=" + objType)
    }
    // console.log("javaClsName=" + javaClsName)
    return javaClsName
  }

  static isJavaClass(curObj, expectedClassName){
    var clsName = FridaAndroidUtil.getJavaClassName(curObj)
    // console.log("clsName=" + clsName)
    var isCls = clsName === expectedClassName
    // console.log("isCls=" + isCls)
    return isCls
  } 

  // convert (Java) map (java.util.HashMap) key=value string list
  static mapToKeyValueStrList(curMap){
    var keyValStrList = []
    var HashMapNode = Java.use('java.util.HashMap$Node')
    // console.log("HashMapNode=" + HashMapNode)
    if((null != curMap) && (curMap != undefined)) {
      var mapEntrySet = curMap.entrySet()
      // console.log("mapEntrySet=" + mapEntrySet)
      if (mapEntrySet != undefined) {
        var iterator = mapEntrySet.iterator()
        // console.log("iterator=" + iterator)
        while (iterator.hasNext()) {
          var entry = Java.cast(iterator.next(), HashMapNode)
          // console.log("entry=" + entry)
          var curKey = entry.getKey()
          var curVal = entry.getValue()
          // console.log("key=" + entry.getKey() + ", value=" + entry.getValue());
          var keyValStr = `${curKey}=${curVal}`
          // console.log("keyValStr=" + keyValStr);
          keyValStrList.push(keyValStr)
        }  
      }  
    }
    // console.log("keyValStrList=" + keyValStrList)
    return keyValStrList
  }

  // convert (Java) map (java.util.HashMap) to string
  //  curMap="<instance: java.util.Map, $className: java.util.HashMap>"
  static mapToStr(curMap){
    // return JSON.stringify(curMap, (key, value) => (value instanceof Map ? [...value] : value));
    // var keyValStrList = this.mapToKeyValueStrList(curMap)
    var keyValStrList = FridaAndroidUtil.mapToKeyValueStrList(curMap)
    // console.log("keyValStrList=" + keyValStrList)
    var mapStr = keyValStrList.join(", ")
    var mapStr = `[${mapStr}]`
    // console.log("mapStr=" + mapStr)
    return mapStr
  }

  static describeJavaClass(className) {
    var jClass = Java.use(className);
    console.log(JSON.stringify({
      _name: className,
      _methods: Object.getOwnPropertyNames(jClass.__proto__).filter(m => {
      // _methods: Object.getOwnPropertyDescriptor(jClass.__proto__).filter(m => {
      // _methods: Object.getOwnPropertySymbols(jClass.__proto__).filter(m => {
        return !m.startsWith('$') // filter out Frida related special properties
           || m == 'class' || m == 'constructor' // optional
      }), 
      _fields: jClass.class.getFields().map(f => {
        return f.toString()
      })  
    }, null, 2))
  }

  // enumerate all methods declared in a Java class
  static enumMethods(targetClass) {
    var hook = Java.use(targetClass);
    var ownMethods = hook.class.getDeclaredMethods();
    console.log("use getDeclaredMethods")

    // var ownMethods = hook.class.getMethods();
    // console.log("use getMethods")

    hook.$dispose;
    return ownMethods;
  }

  // enumerate all property=field declared in a Java class
  static enumProperties(targetClass) {
    var hook = Java.use(targetClass);
    // var ownMethods = hook.class.getFields();
    // console.log("use getFields")

    var ownFields = hook.class.getDeclaredFields();
    console.log("use getDeclaredFields")

    hook.$dispose;
    return ownFields;
  }

  // print single java class all Functions=Methods and Fields=Properties
  static printClassAllMethodsFields(javaClassName) {
    console.log("=============== " + "Class: " + javaClassName + " ===============")

    console.log("-----" + "All Properties" + "-----")
    // var allProperties = enumProperties(javaClassName)
    // var allProperties = this.enumProperties(javaClassName)
    var allProperties = FridaAndroidUtil.enumProperties(javaClassName)
    allProperties.forEach(function(singleProperty) { 
      console.log(singleProperty)
    })

    // console.log("-----" + "All Methods" + "-----")
    // enumerate all methods in a class
    // var allMethods = enumMethods(javaClassName)
    // var allMethods = this.enumMethods(javaClassName)
    var allMethods = FridaAndroidUtil.enumMethods(javaClassName)
    allMethods.forEach(function(singleMethod) { 
      console.log(singleMethod)
    })

    // console.log("")
    console.log("=========== " + "End of class: " + javaClassName + " ===========")
  }

  // generate current stack trace string
  static genStackStr(prefix="") {
    // let newThrowable = ThrowableCls.$new()
    // let newThrowable = this.curThrowableCls.$new()
    let newThrowable = FridaAndroidUtil.curThrowableCls.$new()
    // console.log("genStackStr: newThrowable=" + newThrowable)
    var stackElements = newThrowable.getStackTrace()
    // console.log("genStackStr: stackElements=" + stackElements)
    if (!JsUtil.strIsEmpty(prefix)){
      prefix = prefix + " "
    }
    const linePrefix = "\n  "
    var stackStr = prefix + "Stack:" + linePrefix + stackElements[0] //method//stackElements[0].getMethodName()
    for (var i = 1; i < stackElements.length; i++) {
      stackStr += linePrefix + "at " + stackElements[i]
    }
    // stackStr = "\n\n" + stackStr
    stackStr = stackStr + "\n"
    // console.log("genStackStr: stackStr=" + stackStr)

    return stackStr
  }

  // 打印当前调用堆栈信息 print call stack
  static printStack(prefix="") {
    var stackStr = FridaAndroidUtil.genStackStr(prefix)
    console.log(stackStr)

    // let newThrowable = ThrowableCls.$new()
    // let curLog = Java.use("android.util.Log")
    // let stackStr = curLog.getStackTraceString(newThrowable)
    // console.log("stackStr=" + stackStr)
  }

  // generate Function call string
  static genFunctionCallStr(funcName, funcParaDict){
    var logStr = `${funcName}:`
    // var logStr = funcName + ":"
    var isFirst = true

    for(var curParaName in funcParaDict){
      let curParaValue = funcParaDict[curParaName]
      var prevStr = ""
      if (isFirst){
        prevStr = " "
        isFirst = false
      } else {
        prevStr = ", "
      }

      logStr = `${logStr}${prevStr}${curParaName}=` + curParaValue
      // logStr = logStr + prevStr + curParaName + "=" + curParaValue
    }

    return logStr
  }

  static printFunctionCallStr(funcName, funcParaDict){
    // var functionCallStr = this.genFunctionCallStr(funcName, funcParaDict)
    var functionCallStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)
    console.log(functionCallStr)
  }

  // print Function call and stack trace string
  static printFunctionCallAndStack(funcName, funcParaDict, filterList=undefined){
    // console.log("filterList=" + filterList)

    var needPrint = true

    // var functionCallStr = this.genFunctionCallStr(funcName, funcParaDict)
    var functionCallStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)

    // var stackStr = this.genStackStr()
    // var stackStr = FridaAndroidUtil.genStackStr()
    var stackStr = FridaAndroidUtil.genStackStr(funcName)

    if (filterList != undefined) {
      needPrint = false

      for (const curFilter of filterList) {
        // console.log("curFilter=" + curFilter)
        if (stackStr.includes(curFilter)) {
          needPrint = true
          // console.log("needPrint=" + needPrint)
          break
        }
      }
    }

    if (needPrint) {
      var functionCallAndStackStr = `${functionCallStr}\n${stackStr}`
      // var functionCallAndStackStr = functionCallStr + "\n" + stackStr
    
      // return functionCallAndStackStr
      console.log(functionCallAndStackStr)  
    }
  }

  // find loaded classes that match a pattern (async)
  // Note: for some app, will crash: Process terminated
  static findClass(pattern) {
    console.log("Finding all classes that match pattern: " + pattern + "\n");

    Java.enumerateLoadedClasses({
      onMatch: function(aClass) {
        if (aClass.match(pattern)){
          console.log(aClass)
        }
      },
      onComplete: function() {}
    });
  }

  // emulate print all Java Classes
  // Note: for some app, will crash: Process terminated
  static printAllClasses() {
    // findClass("*")

    Java.enumerateLoadedClasses({
      onMatch: function(className) {
        console.log(className);
      },
      onComplete: function() {}
    });
  }

}

// https://github.com/crifan/crifanLib/blob/master/javascript/frida/FridaHookAndroidJava.js
// Frida hook common Android/Java class
class FridaHookAndroidJava {
  constructor() {
    console.log("FridaHookAndroidJava constructor")
  }

  static JSONObject() {
    /******************** org.json.JSONObject ********************/
    var className_JSONObject = "org.json.JSONObject"
    // FridaAndroidUtil.printClassAllMethodsFields(className_JSONObject)

    var cls_JSONObject = Java.use(className_JSONObject)
    console.log("cls_JSONObject=" + cls_JSONObject)

    // public org.json.JSONObject org.json.JSONObject.put(java.lang.String,java.lang.Object) throws org.json.JSONException
    var func_JSONObject_put = cls_JSONObject.put.overload('java.lang.String', 'java.lang.Object')
    console.log("func_JSONObject_put=" + func_JSONObject_put)
    if (func_JSONObject_put) {
      func_JSONObject_put.implementation = function (str, obj) {
        var funcName = "JSONObject.put(str,obj)"
        var funcParaDict = {
          "str": str,
          "obj": obj,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.put(str, obj)
      }
    }

  }

  static String(callback_String_equals=null) {
    /******************** java.lang.String ********************/
    var className_String = "java.lang.String"
    // FridaAndroidUtil.printClassAllMethodsFields(className_String)

    var cls_String = Java.use(className_String)
    console.log("cls_String=" + cls_String)

    // public String(String original)
    var func_String_ctor = cls_String.$init.overload('java.lang.String')
    // var func_String_ctor = cls_String.getInstance.overload('java.lang.String')
    // var func_String_ctor = cls_String.$new.overload('java.lang.String')
    console.log("func_String_ctor=" + func_String_ctor)
    if (func_String_ctor) {
      func_String_ctor.implementation = function (original) {
        var funcName = "String(orig)"
        var funcParaDict = {
          "original": original,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.$init(original)
      }
    }

    // public boolean equals(Object anObject)
    // public boolean java.lang.String.equals(java.lang.Object)
    var func_String_equals = cls_String.equals
    console.log("func_String_equals=" + func_String_equals)
    if (func_String_equals) {
      func_String_equals.implementation = function (anObject) {
        var funcName = "String.equals(anObject)"
        var funcParaDict = {
          "anObject": anObject,
        }

        var isPrintStack = false
        if(null != callback_String_equals) {
          isPrintStack = callback_String_equals(anObject)
        }

        if(isPrintStack){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        return this.equals(anObject)
      }
    }

  }

  static URL(callback_isPrintStack_URL_init=null) {
    var className_URL = "java.net.URL"
    // FridaAndroidUtil.printClassAllMethodsFields(className_URL)

    var cls_URL = Java.use(className_URL)
    console.log("cls_URL=" + cls_URL)

    // public URL(String url)
    // var func_URL_init = cls_URL.$init
    var func_URL_init = cls_URL.$init.overload('java.lang.String')
    console.log("func_URL_init=" + func_URL_init)
    if (func_URL_init) {
      func_URL_init.implementation = function (url) {
        var funcName = "URL(url)"
        var funcParaDict = {
          "url": url,
        }

        var isPrintStack = false
        if (null != callback_isPrintStack_URL_init){
          isPrintStack = callback_isPrintStack_URL_init(url)
        }

        if (isPrintStack){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        return this.$init(url)
      }
    }
  }

  static HashMap(callback_isPrintStack_put=null, callback_isPrintStack_putAll=null, callback_isPrintStack_get=null) {
    /******************** java.util.HashMap ********************/
    var className_HashMap = "java.util.HashMap"
    // FridaAndroidUtil.printClassAllMethodsFields(className_HashMap)

    var cls_HashMap = Java.use(className_HashMap)
    console.log("cls_HashMap=" + cls_HashMap)
    // var instance_HashMap = cls_HashMap.$new()
    // console.log("instance_HashMap=" + instance_HashMap)

    // public java.lang.Object java.util.HashMap.put(java.lang.Object,java.lang.Object)
    // var func_HashMap_put = cls_HashMap.put('java.lang.Object', 'java.lang.Object')
    // var func_HashMap_put = instance_HashMap.put('java.lang.Object', 'java.lang.Object')
    var func_HashMap_put = cls_HashMap.put
    console.log("func_HashMap_put=" + func_HashMap_put)
    if (func_HashMap_put) {
      func_HashMap_put.implementation = function (keyObj, valueObj) {
        var funcName = "HashMap.put(key,val)"
        var funcParaDict = {
          "keyObj": keyObj,
          "valueObj": valueObj,
        }

        if (null != keyObj) {
          // console.log("keyObj=" + keyObj)
          // console.log("keyObj.value=" + keyObj.value)
          // console.log("keyObj=" + keyObj + ", valueObj=" + valueObj)

          var isPrintStack = false

          // isPrintStack = HookDouyin_feedUrl.HashMap(keyObj, valueObj)
          if (null != callback_isPrintStack_put){
            isPrintStack = callback_isPrintStack_put(keyObj, valueObj)
          }

          if (isPrintStack) {
            FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
          }
        }

        return this.put(keyObj, valueObj)
      }
    }

    // public void java.util.HashMap.putAll(java.util.Map)
    // var func_HashMap_putAll = cls_HashMap.putAll('java.util.Map')
    var func_HashMap_putAll = cls_HashMap.putAll
    console.log("func_HashMap_putAll=" + func_HashMap_putAll)
    if (func_HashMap_putAll) {
      func_HashMap_putAll.implementation = function (newMap) {
        var funcName = "HashMap.putAll(map)"
        var funcParaDict = {
          "newMap": newMap,
        }
        // console.log("newMap=" + newMap)
        var isPrintStack = false
        if (null != callback_isPrintStack_putAll){
          isPrintStack = callback_isPrintStack_putAll(newMap)
        }

        if (isPrintStack){
          console.log("newMapStr=" + FridaAndroidUtil.mapToStr(newMap))
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        return this.putAll(newMap)
      }
    }

    // https://docs.oracle.com/javase/8/docs/api/java/util/HashMap.html#get-java.lang.Object-
    // public V get(Object key)
    var func_HashMap_get = cls_HashMap.get
    console.log("func_HashMap_get=" + func_HashMap_get)
    if (func_HashMap_get) {
      func_HashMap_get.implementation = function (keyObj) {
        var funcName = "HashMap.get(key)"
        var funcParaDict = {
          "keyObj": keyObj,
        }

        var isPrintStack = false
        if (null != callback_isPrintStack_get){
          isPrintStack = callback_isPrintStack_get(keyObj)
        }

        if (isPrintStack){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        var retValObj = this.get(keyObj)
        if (isPrintStack){
          console.log("retValObj=" + retValObj)
        }
        return retValObj
      }
    }

  }
  
  static LinkedHashMap() {
    /******************** java.util.LinkedHashMap ********************/
    var className_LinkedHashMap = "java.util.LinkedHashMap"
    // FridaAndroidUtil.printClassAllMethodsFields(className_LinkedHashMap)

    var cls_LinkedHashMap = Java.use(className_LinkedHashMap)
    console.log("cls_LinkedHashMap=" + cls_LinkedHashMap)

  }

  static RandomAccessFile() {
    /******************** java.io.RandomAccessFile ********************/
    var className_RandomAccessFile = "java.io.RandomAccessFile"
    // FridaAndroidUtil.printClassAllMethodsFields(className_RandomAccessFile)

    var cls_RandomAccessFile = Java.use(className_RandomAccessFile)
    console.log("cls_RandomAccessFile=" + cls_RandomAccessFile)

    // public final java.nio.channels.FileChannel java.io.RandomAccessFile.getChannel()
    var func_RandomAccessFile_getChannel = cls_RandomAccessFile.getChannel
    console.log("func_RandomAccessFile_getChannel=" + func_RandomAccessFile_getChannel)
    if (func_RandomAccessFile_getChannel) {
      func_RandomAccessFile_getChannel.implementation = function () {
        var funcName = "RandomAccessFile.getChannel()"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var fileChannel = this.getChannel()
        console.log("fileChannel=" + fileChannel)
        var filePathValue = this.path.value
        console.log("filePathValue=" + filePathValue)
        return fileChannel
      }
    }
  }

  static NetworkRequest_Builder(){
    var clsName_NetworkRequest_Builder = "android.net.NetworkRequest$Builder"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_NetworkRequest_Builder)

    var cls_NetworkRequest_Builder = Java.use(clsName_NetworkRequest_Builder)
    console.log("cls_NetworkRequest_Builder=" + cls_NetworkRequest_Builder)

    // public Builder ()
    var func_NetworkRequest_Builder_ctor_void = cls_NetworkRequest_Builder.$init.overload()
    console.log("func_NetworkRequest_Builder_ctor_void=" + func_NetworkRequest_Builder_ctor_void)
    if (func_NetworkRequest_Builder_ctor_void) {
      func_NetworkRequest_Builder_ctor_void.implementation = function () {
        var funcName = "NetworkRequest$Builder()"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var newBuilder_void = this.$init()
        console.log("newBuilder_void=" + newBuilder_void)
        return newBuilder_void
      }
    }

    // // Note: Xiaomi8 not exist: .overload('android.net.NetworkRequest')
    // //    -> Error: NetworkRequest$Builder(): specified argument types do not match any of: .overload()
    // // public Builder (NetworkRequest request)
    // var func_NetworkRequest_Builder_ctor_req = cls_NetworkRequest_Builder.$init.overload('android.net.NetworkRequest')
    // console.log("func_NetworkRequest_Builder_ctor_req=" + func_NetworkRequest_Builder_ctor_req)
    // if (func_NetworkRequest_Builder_ctor_req) {
    //   func_NetworkRequest_Builder_ctor_req.implementation = function (request) {
    //     var funcName = "NetworkRequest$Builder(request)"
    //     var funcParaDict = {
    //     }
    //     FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
    //     var newBuilder_req = this.$init(request)
    //     console.log("newBuilder_req=" + newBuilder_req)
    //     return newBuilder_req
    //   }
    // }

  }

  static File(callback_File_ctor_str=null) {
    var className_File = "java.io.File"
    // FridaAndroidUtil.printClassAllMethodsFields(className_File)

    var cls_File = Java.use(className_File)
    console.log("cls_File=" + cls_File)

    // File(String pathname)
    var func_File_ctor_path = cls_File.$init.overload('java.lang.String')
    console.log("func_File_ctor_path=" + func_File_ctor_path)
    if (func_File_ctor_path) {
      func_File_ctor_path.implementation = function (pathname) {
        var funcName = "File(pathname)"
        var funcParaDict = {
          "pathname": pathname,
        }

        var isMatch = false
        if (null != callback_File_ctor_str){
          isMatch = callback_File_ctor_str(pathname)
        }

        if (isMatch){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        // tmp use previould check to bypass new File
        // if (isMatch) {
        //   // return null
        //   pathname = "" // hook bypass return empty File by empty filename
        // }

        var retFile_ctor_path = this.$init(pathname)

        // if (isMatch) {
          console.log("pathname=" + pathname + " => retFile_ctor_path=" + retFile_ctor_path)
        // }

        return retFile_ctor_path
      }
    }

    // public boolean exists ()
    var func_File_exists = cls_File.exists
    console.log("func_File_exists=" + func_File_exists)
    if (func_File_exists) {
      func_File_exists.implementation = function () {
        var funcName = "File.exists()"
        var funcParaDict = {
        }

        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBool_File_exists = this.exists()
        var fileAbsPath = this.getAbsolutePath()
        console.log("fileAbsPath=" + fileAbsPath + " => retBool_File_exists=" + retBool_File_exists)
        return retBool_File_exists
      }
    }

  }

  static Settings_getInt(cls_Settings, Settings_getInt_crName=null, Settings_getInt_crNameDef=null) {
    // static int	getInt(ContentResolver cr, String name)
    // public static int android.provider.Settings$Global.getInt(android.content.ContentResolver,java.lang.String) throws android.provider.Settings$SettingNotFoundException

    // public static int getInt (ContentResolver cr, String name)
    // public static int android.provider.Settings$Secure.getInt(android.content.ContentResolver,java.lang.String) throws android.provider.Settings$SettingNotFoundException

    var func_Settings_getInt_crName = cls_Settings.getInt.overload("android.content.ContentResolver", "java.lang.String")
    console.log("func_Settings_getInt_crName=" + func_Settings_getInt_crName)
    if (func_Settings_getInt_crName) {
      func_Settings_getInt_crName.implementation = function (cr, name) {
        var funcName = "getInt(cr,name)"
        var funcParaDict = {
          "cr": cr,
          "name": name,
        }

        var isMatch = false
        if (null != Settings_getInt_crName){
          isMatch = Settings_getInt_crName(cr, name)
        }

        var retInt_Settings_getInt_crName = 0

        if (isMatch){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

          // retInt_Settings_getInt_crName = 0 // do hook bypass for development_settings_enabled, adb_enabled
          retInt_Settings_getInt_crName = this.getInt(cr, name) // no hook
        } else {
          retInt_Settings_getInt_crName = this.getInt(cr, name)
        }

        console.log("name" + name + " => retInt_Settings_getInt_crName=" + retInt_Settings_getInt_crName)
        return retInt_Settings_getInt_crName
      }
    }

    // static int	getInt(ContentResolver cr, String name, int def)
    // public static int android.provider.Settings$Global.getInt(android.content.ContentResolver,java.lang.String,int)

    // static int	getInt(ContentResolver cr, String name, int def)
    // public static int android.provider.Settings$Secure.getInt(android.content.ContentResolver,java.lang.String,int)

    var func_Settings_getInt_crNameDef = cls_Settings.getInt.overload("android.content.ContentResolver", "java.lang.String", "int")
    console.log("func_Settings_getInt_crNameDef=" + func_Settings_getInt_crNameDef)
    if (func_Settings_getInt_crNameDef) {
      func_Settings_getInt_crNameDef.implementation = function (cr, name, def) {
        var funcName = "getInt(cr,name,def)"
        var funcParaDict = {
          "cr": cr,
          "name": name,
          "def": def,
        }

        var isMatch = false
        if (null != Settings_getInt_crNameDef){
          isMatch = Settings_getInt_crNameDef(cr, name, def)
        }

        var retInt_Settings_getInt_crNameDef = 0

        if (isMatch){
          console.log("isMatch=" + isMatch)
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

          // retInt_Settings_getInt_crNameDef = 0 // do hook bypass for development_settings_enabled, adb_enabled
          retInt_Settings_getInt_crNameDef = this.getInt(cr, name, def) // no hook
        } else {
          retInt_Settings_getInt_crNameDef = this.getInt(cr, name, def)
        }

        console.log("name=" + name + " => retInt_Settings_getInt_crNameDef=" + retInt_Settings_getInt_crNameDef)
        return retInt_Settings_getInt_crNameDef
      }
    }

  }

  static SettingsGlobal(SettingsGlobal_getInt_crName=null, SettingsGlobal_getInt_crNameDef=null) {
    var className_SettingsGlobal = "android.provider.Settings$Global"
    // FridaAndroidUtil.printClassAllMethodsFields(className_SettingsGlobal)

    var cls_SettingsGlobal = Java.use(className_SettingsGlobal)
    console.log("cls_SettingsGlobal=" + cls_SettingsGlobal)

    FridaHookAndroidJava.Settings_getInt(cls_SettingsGlobal, SettingsGlobal_getInt_crName, SettingsGlobal_getInt_crNameDef)
  }

  static SettingsSecure(SettingsSecure_getInt_crName=null, SettingsSecure_getInt_crNameDef=null) {
    var className_SettingsSecure = "android.provider.Settings$Secure"
    // FridaAndroidUtil.printClassAllMethodsFields(className_SettingsSecure)

    var cls_SettingsSecure = Java.use(className_SettingsSecure)
    console.log("cls_SettingsSecure=" + cls_SettingsSecure)

    FridaHookAndroidJava.Settings_getInt(cls_SettingsSecure, SettingsSecure_getInt_crName, SettingsSecure_getInt_crNameDef)
  }

  static NetworkInterface(NetworkInterface_getName=null) {
    var className_NetworkInterface = "java.net.NetworkInterface"
    // FridaAndroidUtil.printClassAllMethodsFields(className_NetworkInterface)

    var cls_NetworkInterface = Java.use(className_NetworkInterface)
    console.log("cls_NetworkInterface=" + cls_NetworkInterface)

    // public String getName()
    // public java.lang.String java.net.NetworkInterface.getName()
    var func_NetworkInterface_getName = cls_NetworkInterface.getName
    console.log("func_NetworkInterface_getName=" + func_NetworkInterface_getName)
    if (func_NetworkInterface_getName) {
      func_NetworkInterface_getName.implementation = function () {
        var funcName = "NetworkInterface.getName()"
        var funcParaDict = {
        }

        var retName = this.getName()

        var isMatch = false
        if (null != NetworkInterface_getName){
          isMatch = NetworkInterface_getName(retName)
        }

        if (isMatch){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

          // do hook bypass
          // retName = "fakeName"
          // retName = ""

          // no hook
        } else {
          // no hook
        }

        console.log("retName=" + retName)
        return retName
      }
    }

  }

  static PackageManager(PackageManager_getApplicationInfo=null) {
    var className_PackageManager = "android.content.pm.PackageManager"
    // FridaAndroidUtil.printClassAllMethodsFields(className_PackageManager)

    var cls_PackageManager = Java.use(className_PackageManager)
    console.log("cls_PackageManager=" + cls_PackageManager)

    // // Note: Xiaomi8 not exist: getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager$ApplicationInfoFlags')
    // // public ApplicationInfo getApplicationInfo(String packageName, PackageManager.ApplicationInfoFlags flags)
    // // public android.content.pm.ApplicationInfo android.content.pm.PackageManager.getApplicationInfo(java.lang.String,android.content.pm.PackageManager$ApplicationInfoFlags) throws android.content.pm.PackageManager$NameNotFoundException
    // // var func_PackageManager_getApplicationInfo = cls_PackageManager.getApplicationInfo
    // var func_PackageManager_getApplicationInfo = cls_PackageManager.getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager$ApplicationInfoFlags')
    // // var func_PackageManager_getApplicationInfo = cls_PackageManager.getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager.ApplicationInfoFlags')
    // console.log("func_PackageManager_getApplicationInfo=" + func_PackageManager_getApplicationInfo)
    // if (func_PackageManager_getApplicationInfo) {
    //   func_PackageManager_getApplicationInfo.implementation = function (packageName, flags) {
    //     var funcName = "PackageManager.getApplicationInfo(packageName,flags)"
    //     var funcParaDict = {
    //       "packageName": packageName,
    //       "flags": flags,
    //     }

    //     var retAppInfo = this.getApplicationInfo(packageName, flags)

    //     var isMatch = false
    //     if (null != PackageManager_getApplicationInfo){
    //       isMatch = PackageManager_getApplicationInfo(packageName)
    //     }

    //     if (isMatch){
    //       FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

    //       // do hook bypass
    //       retAppInfo = ApplicationInfo()
    //     } else {
    //       // no hook
    //     }

    //     console.log("retAppInfo=" + retAppInfo)
    //     return retAppInfo
    //   }
    // }

    // public abstract ApplicationInfo getApplicationInfo (String packageName, int flags)
    // public abstract android.content.pm.ApplicationInfo android.content.pm.PackageManager.getApplicationInfo(java.lang.String,int) throws android.content.pm.PackageManager$NameNotFoundException
    var func_PackageManager_getApplicationInfo_abstract = cls_PackageManager.getApplicationInfo.overload('java.lang.String', 'int')
    console.log("func_PackageManager_getApplicationInfo_abstract=" + func_PackageManager_getApplicationInfo_abstract)
    if (func_PackageManager_getApplicationInfo_abstract) {
      func_PackageManager_getApplicationInfo_abstract.implementation = function (pkgName, flags) {
        var funcName = "PackageManager.getApplicationInfo(pkgName,flags)"
        var funcParaDict = {
          "pkgName": pkgName,
          "flags": flags,
        }

        var retAppInfo_abstract = this.getApplicationInfo(pkgName, flags)

        var isMatch = false
        if (null != PackageManager_getApplicationInfo){
          isMatch = PackageManager_getApplicationInfo(pkgName)
        }

        if (isMatch){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

          // // do hook bypass
          // retAppInfo_abstract = ApplicationInfo()
        } else {
          // no hook
        }

        console.log("retAppInfo_abstract=" + retAppInfo_abstract)
        return retAppInfo_abstract
      }
    }

  }

  static System(callback_isMatch_System_getProperty=null) {
    var className_System = "java.lang.System"
    // FridaAndroidUtil.printClassAllMethodsFields(className_System)

    var cls_System = Java.use(className_System)
    console.log("cls_System=" + cls_System)

    // public static String getProperty(String key) 
    // public static java.lang.String java.lang.System.getProperty(java.lang.String)
    var func_System_getProperty_key = cls_System.getProperty.overload('java.lang.String')
    console.log("func_System_getProperty_key=" + func_System_getProperty_key)
    if (func_System_getProperty_key) {
      func_System_getProperty_key.implementation = function (key) {
        var funcName = "System.getProperty(key)"
        var funcParaDict = {
          "key": key,
        }

        var isMatch = false
        if (null != callback_isMatch_System_getProperty){
          isMatch = callback_isMatch_System_getProperty(key)
        }

        if (isMatch){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        var retPropVal = this.getProperty(key)
        if (isMatch){
          retPropVal = null // enable hook bypass: return null
          console.log("key=" + key + " -> hooked retPropVal=" + retPropVal)
        } else {
          console.log("key=" + key + " -> retPropVal=" + retPropVal)
        }

        return retPropVal
      }
    }
  }

}

// https://github.com/crifan/crifanLib/blob/master/javascript/frida/FridaHookAndroidNative.js
// Frida hook Android native functions
class FridaHookAndroidNative {
  constructor() {
    console.log("FridaHookAndroidNative constructor")
  }

  static JNI_OnLoad(libFullPath) {
    // jint JNI_OnLoad(JavaVM *vm, void *reserved)
    const funcSym = "JNI_OnLoad"
    const funcPtr = Module.findExportByName(libFullPath, funcSym)
    console.log("[+] Hooking " + funcSym + ", funcPtr=" + funcPtr)
    if (null != funcPtr){
      var funcHook = Interceptor.attach(funcPtr, {
        onEnter: function (args) {
          const vm = args[0]
          const reserved = args[1]
          console.log("[+] " + funcSym + "(" + vm + ", " + reserved + ") called")
        },
        onLeave: function (retval) {
          console.log("[+]\t= " + retval)
        }
      })  
    }
  }

}

// https://github.com/crifan/crifanLib/blob/master/javascript/frida/FridaHookNative.js
// Frida hook common native functions
class FridaHookNative {
  static dladdr = null
  static free = null

  constructor() {
    console.log("FridaHookNative constructor")
  }

  static {
    FridaHookNative.dladdr = FridaHookNative.genNativeFunc_dladdr()
    console.log("FridaHookNative.dladdr=" + FridaHookNative.dladdr)

    FridaHookNative.free = FridaHookNative.genNativeFunc_free()
    console.log("FridaHookNative.free=" + FridaHookNative.free)
  }

  static genNativeFunc_dladdr(){
    var newNativeFunc_dladdr = null
    /*
      int dladdr(const void *, Dl_info *);

      typedef struct dl_info {
              const char      *dli_fname;     // Pathname of shared object
              void            *dli_fbase;     // Base address of shared object
              const char      *dli_sname;     // Name of nearest symbol
              void            *dli_saddr;     // Address of nearest symbol
      } Dl_info;
    */
    var origNativeFunc_dladdr = Module.findExportByName(null, 'dladdr')
    // console.log("origNativeFunc_dladdr=" + origNativeFunc_dladdr)
    if (null != origNativeFunc_dladdr) {
      newNativeFunc_dladdr = new NativeFunction(
        origNativeFunc_dladdr,
        'int',
        ['pointer','pointer']
      )
    }
    return newNativeFunc_dladdr
  }

  static genNativeFunc_free(){
    // void free(void *ptr)
    var newNativeFunc_free = null
    var origNativeFunc_free = Module.findExportByName(null, "free")
    // console.log("origNativeFunc_free=" + origNativeFunc_free)
    if (null != origNativeFunc_free) {
      newNativeFunc_free = new NativeFunction(
        origNativeFunc_free,
        'void',
        ['pointer']
      )
    }
    return newNativeFunc_free
  }

  static hookNative_dlopen(){
    // void *dlopen(const char *filename, int flags);
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
      onEnter: function (args) {
        var filename = FridaUtil.ptrToCStr(args[0])
        var flags = args[1]
        console.log("dlopen: [+] filename=" + filename + ", flags=" + flags)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_open(){
    // int open(const char *pathname, int flags, mode_t mode);
    Interceptor.attach(Module.findExportByName(null, "open"), {
      onEnter: function (args) {
        var path = FridaUtil.ptrToCStr(args[0])
        var oflags = args[1]
        // console.log("open: [+] path=" + path + ", oflags=" + oflags)
        this._path = path
        this._oflags = oflags
      },
      onLeave: function (retFd) {
        // console.log("\t open retFd=" + retFd)
        console.log("open: [+] path=" + this._path + ", oflags=" + this._oflags + " -> retFd=" + retFd)
      }
    })
  }

  static hookNative_read(){
    // ssize_t read(int fd, void buf[.count], size_t count)
    Interceptor.attach(Module.findExportByName(null, "read"), {
      onEnter: function (args) {
        var fd = args[0]
        var buf = args[1]
        var count = args[2]
        console.log("read: fd=" + fd + ", buf=" + buf + ", count=" + count)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_write(){
    // ssize_t write(int fildes, const void *buf, size_t nbyte)
    Interceptor.attach(Module.findExportByName(null, "write"), {
      onEnter: function (args) {
        var fildes = args[0]
        var buf = args[1]
        var nbyte = args[2]
        console.log("write: fildes=" + fildes + ", buf=" + buf + ", nbyte=" + nbyte)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_close(){
    // int close(int fd)
    Interceptor.attach(Module.findExportByName(null, "close"), {
      onEnter: function (args) {
        var fd = args[0]
        console.log("close: fd=" + fd)
      },
      onLeave: function (retval) {
      }
    })
  }

  static hookNative_remove(){
    // int remove(const char *path)
    Interceptor.attach(Module.findExportByName(null, "remove"), {
      onEnter: function (args) {
        var path = FridaUtil.ptrToCStr(args[0])
        console.log("remove: path=" + path)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_fopen(){
    // FILE *fopen(const char *filename, const char *mode);
    // FILE *fopen(const char *restrict pathname, const char *restrict mode);
  
    Interceptor.attach(Module.findExportByName(null, "fopen"), {
      onEnter: function (args) {
        var pathname = FridaUtil.ptrToCStr(args[0])
        var mode = FridaUtil.ptrToCStr(args[1])
        // console.log("fopen: pathname=" + pathname + ", mode=" + mode)
        this._pathname = pathname
        this._mode = mode
      },
      onLeave: function (retFile) {
        // console.log("fopen: retFile=" + retFile)
        console.log("fopen: pathname=" + this._pathname + ", mode=" + this._mode + " -> retFile=" + retFile)
      }
    })
  
    // var FuncPtr_fopen = Module.findExportByName(null, "fopen")
    // console.log("FuncPtr_fopen=" + FuncPtr_fopen)
    // if (null != FuncPtr_fopen) {
    //   var func_fopen = new NativeFunction(FuncPtr_fopen, 'pointer', ['pointer', 'pointer'])
    //   console.log("func_fopen=" + func_fopen)
    //   Interceptor.replace(func_fopen,
    //     new NativeCallback(function (filename, mode) {
    //       // console.log("filename=" + filename + ", mode=" + mode)
    //       var filenameStr = filename.readUtf8String()
    //       // console.log("filenameStr=" + filenameStr)
    //       var modeStr = mode.readUtf8String()
    //       // console.log("modeStr=" + modeStr)
    //       var retFile = func_fopen(filename, mode)
    //       // console.log("retFile=" + retFile)
    //       console.log("filename=" + filename + "=" + filenameStr + ", mode=" + mode + "=" + modeStr + "-> retFile" + retFile)
    //       return retFile
    //     },
    //     'pointer',
    //     ['pointer', 'pointer'])
    //   )
    // }
  
  }

  static hookNative_flock(){
    // int flock(int fd, int operation);
    Interceptor.attach(Module.findExportByName(null, "flock"), {
      onEnter: function (args) {
        var fd = args[0]
        var operation = args[1]
        console.log("flock: fd=" + fd + ", operation=" + operation)
      },
      onLeave: function (retval) {
      }
    });
  }

  static hookNative_strcpy(){
    const KnownStrLis = [
      "",
      "/",
      "zh",
      "CN",
      "zh_CN",
      "Hans",
      "zh_Hans",
      "zh_Hans_CN",
      "en",
      "US",
      "en_US",
    ]
  
    // char *strcpy(char *restrict dst, const char *restrict src);
    Interceptor.attach(Module.findExportByName(null, "strcpy"), {
      onEnter: function (args) {
        var dst = FridaUtil.ptrToCStr(args[0])
        var src = FridaUtil.ptrToCStr(args[1])
        if (!KnownStrLis.includes(src)) {
          console.log("strcpy: dst=" + dst + ", src=" + src)
        }
      },
      onLeave: function (args) {
      }
    })
  }
  
  static hookNative_strlen(){
    // size_t strlen(const char *str)
    Interceptor.attach(Module.findExportByName(null, "strlen"), {
      onEnter: function (args) {
        var str = FridaUtil.ptrToCStr(args[0])
        console.log("strlen: str=" + str)
      },
      onLeave: function (args) {
      }
    })

    // var FuncPtr_strlen = Module.findExportByName(null, "strlen")
    // console.log("FuncPtr_strlen=" + FuncPtr_strlen)
    // if (null != FuncPtr_strlen) {
    //   var func_strlen = new NativeFunction(FuncPtr_strlen, 'int', ['pointer'])
    //   console.log("func_strlen=" + func_strlen)
    //   Interceptor.replace(func_strlen,
    //     new NativeCallback(function (cStr) {
    //       // console.log("cStr=" + cStr)
    //       var jsStr = cStr.readUtf8String()
    //       console.log("jsStr=" + jsStr)
    //       var retLen = func_strlen(cStr)
    //       // console.log("retLen=" + retLen)
    //       return retLen
    //     },
    //     'int',
    //     ['pointer'])
    //   );
    // }

  }
  
  static hookNative_strncpy(){
    // char *strncpy(char *dest, const char *src, size_t count);
    Interceptor.attach(Module.findExportByName(null, "strncpy"), {
      onEnter: function (args) {
        var dest = FridaUtil.ptrToCStr(args[0])
        var src = FridaUtil.ptrToCStr(args[1])
        var count = args[2]
        console.log("strncpy: dest=" + dest + ", src=" + src + ", count=" + count)
      },
      onLeave: function (args) {
      }
    })
  }
  
  static hookNative_strcat(){
    // char *strcat(char *restrict dst, const char *restrict src);
    Interceptor.attach(Module.findExportByName(null, "strcat"), {
      onEnter: function (args) {
        var dst = FridaUtil.ptrToCStr(args[0])
        var src = FridaUtil.ptrToCStr(args[1])
        console.log("strcat: dst=" + dst + ", src=" + src)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_execlp(){
    // int execlp(const char *path, const char *arg0, ..., NULL);
    Interceptor.attach(Module.findExportByName(null, "execlp"), {
      onEnter: function (args) {
        var path = FridaUtil.ptrToCStr(args[0])
        var arg0 = FridaUtil.ptrToCStr(args[1])
        var arg1 = FridaUtil.ptrToCStr(args[2])
        console.log("execlp: path=" + path + ", arg0=" + arg0 + ", arg1=" + arg1)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_execv(){
    // int execv(const char *pathname, char *const argv[]);
    Interceptor.attach(Module.findExportByName(null, "execv"), {
      onEnter: function (args) {
        var pathname = FridaUtil.ptrToCStr(args[0])
        var argv = args[1]
        console.log("execv: pathname=" + pathname + ", argv=" + argv)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_pthread_create(){
    // int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void*), void *arg);
    Interceptor.attach(Module.findExportByName(null, "pthread_create"), {
      onEnter: function (args) {
        var thread = args[0]
        var attr = args[1]
        var start_routine = args[2]
        var arg = args[3]
        console.log("pthread_create: thread=" + thread + ", attr=" + attr + ", start_routine=" + start_routine + ", arg=" + arg)
      },
      onLeave: function (retNewPid) {
        console.log("\t pthread_create retNewPid= " + retNewPid)
      }
    })
  }

  static hookNative_clone(){
    // int clone(int (*fn)(void *_Nullable), void *stack, int flags, void *_Nullable arg, ...  /* pid_t *_Nullable parent_tid, void *_Nullable tls, pid_t *_Nullable child_tid */ );
    Interceptor.attach(Module.findExportByName(null, "clone"), {
      onEnter: function (args) {
        var fn = args[0]
        var stack = args[1]
        var flags = args[2]
        var arg = args[3]
        console.log("clone: fn=" + fn + ", stack=" + stack + ", flags=" + flags + ", arg=" + arg)
      },
      onLeave: function (retval) {
      }
    })
  }

  static hookNative_fork(){
    // pid_t fork(void);
    Interceptor.attach(Module.findExportByName(null, "fork"), {
      onEnter: function (args) {
        console.log("fork called")
      },
      onLeave: function (retval) {
        console.log("\t fork retval= " + retval)
      }
    })
  }

  static hookNative_posix_spawn(){
    // int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]);
    Interceptor.attach(Module.findExportByName(null, "posix_spawn"), {
      onEnter: function (args) {
        var pid = args[0]
        var path = FridaUtil.ptrToCStr(args[1])
        var file_actions = args[2]
        var attrp = args[3]
        var argv = args[4]
        var envp = args[5]
        console.log("posix_spawn: pid=" + pid + ", path=" + path + ", file_actions=" + file_actions + ", attrp=" + attrp + ", argv=" + argv + ", envp=" + envp)
      },
      onLeave: function (retval) {
      }
    })
  }

  static hookNative_posix_spawnp(){
    // int posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]);
    Interceptor.attach(Module.findExportByName(null, "posix_spawnp"), {
      onEnter: function (args) {
        var pid = args[0]
        var file = FridaUtil.ptrToCStr(args[1])
        var file_actions = args[2]
        var attrp = args[3]
        var argv = args[4]
        var envp = args[5]
        console.log("posix_spawnp: pid=" + pid + ", file=" + file + ", file_actions=" + file_actions + ", attrp=" + attrp + ", argv=" + argv + ", envp=" + envp)
      },
      onLeave: function (retval) {
      }
    })
  }

  static hookNative_sigaction(){
    // int sigaction(int signum, const struct sigaction *_Nullable restrict act, struct sigaction *_Nullable restrict oldact);
    Interceptor.attach(Module.findExportByName(null, "sigaction"), {
      onEnter: function (args) {
        var signum = args[0]
        var actP = args[1]
        var oldactP = args[2]
        console.log("sigaction: signum=" + signum + ", actP=" + actP + ", oldactP=" + oldactP)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_killpg(){
    // int killpg(int pgrp, int sig)
    Interceptor.attach(Module.findExportByName(null, "killpg"), {
      onEnter: function (args) {
        var pgrp = args[0]
        var sig = args[1]
        console.log("killpg: pgrp=" + pgrp + ", sig=" + sig)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_pread(){
    // ssize_t pread(int fildes, void *buf, size_t nbyte, off_t offset)
    Interceptor.attach(Module.findExportByName(null, "pread"), {
      onEnter: function (args) {
        var fildes = args[0]
        var buf = args[1]
        var nbyte = args[2]
        var offset = args[3]
        console.log("pread: fildes=" + fildes + ", buf=" + buf + ", nbyte=" + nbyte + ", offset=" + offset)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_pwrite(){
    // ssize_t pwrite(int fildes, const void *buf, size_t nbyte, off_t offset)
    Interceptor.attach(Module.findExportByName(null, "pwrite"), {
      onEnter: function (args) {
        var fildes = args[0]
        var buf = args[1]
        var nbyte = args[2]
        var offset = args[3]
        console.log("pwrite: fildes=" + fildes + ", buf=" + buf + ", nbyte=" + nbyte + ", offset=" + offset)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_pipe(){
    // int pipe(int pipefd[2])
    Interceptor.attach(Module.findExportByName(null, "pipe"), {
      onEnter: function (args) {
        var pipefdArray = args[0]
        console.log("pipe: pipefdArray=" + pipefdArray)
      },
      onLeave: function (retval) {
      }
    })
  }

  static hookNative_getpid(){
    // pid_t getpid(void)
    Interceptor.attach(Module.findExportByName(null, "getpid"), {
      onEnter: function (args) {
        // console.log("getpid called")
      },
      onLeave: function (retPid) {
        console.log("\t getpid retPid=" + retPid)
      }
    })
  }

  static hookNative_getppid(){
    // pid_t getppid(void)
    Interceptor.attach(Module.findExportByName(null, "getppid"), {
      onEnter: function (args) {
        console.log("getppid called")
      },
      onLeave: function (retval) {
        console.log("\t getppid retval=" + retval)
      }
    })
  }

  static hookNative_setsid(){
    // pid_t setsid(void)
    Interceptor.attach(Module.findExportByName(null, "setsid"), {
      onEnter: function (args) {
        console.log("setsid called")
      },
      onLeave: function (retval) {
        console.log("\t setsid retval=" + retval)
      }
    })
  }

}

/*******************************************************************************
 * Common Hook
*******************************************************************************/

class Hook_SomeApp {
  static MapKeyList = ["Accept-Encrypt"]

  static UrlPartList = [".com"]

  // static SettingsGetIntKeyList = ["development_settings_enabled"]
  static SettingsGetIntKeyList = ["development_settings_enabled", "adb_enabled"]
  
  static NetworkInterfaceNameList = ["tun0", "ppp0"]
  // static NetworkInterfaceNameList = ["rmnet_data0"] // for debug
  
  static AppPackageNameList = ["com.tencent.mm"]

  static SystemPropertyKeyList = [
    /*---------- Proxy related ----------*/
    // http
    "http.proxyHost",
    "http.proxyPort",
    "http.nonProxyHosts",
    // https
    "https.proxyHost",
    "https.proxyPort",
    "https.nonProxyHosts",
    // ftp
    "ftp.proxyHost",
    "ftp.proxyPort",
    "ftp.nonProxyHosts",
    // socks
    "socksProxyHost",
    "socksProxyPort",
    //other
    "proxyHost",
  ]

  static {
    // console.log("static UrlPartList=" + Hook_SomeApp.UrlPartList)
    // console.log("static typeof(UrlPartList)=" + typeof(Hook_SomeApp.UrlPartList))
  }

  constructor() {
    console.log("Hook_SomeApp constructor")

    // console.log("UrlPartList=" + Hook_SomeApp.UrlPartList)
    // console.log("typeof(UrlPartList)=" + typeof(Hook_SomeApp.UrlPartList))
  }

  static URL_init(url){
    var isPrintStack = false

    var urlStr = url.toString()
    console.log("urlStr=" + urlStr)
    // console.log("UrlPartList=" + Hook_SomeApp.UrlPartList)

    // for(var eachUrlPart in Hook_SomeApp.UrlPartList) {
    for (let i = 0; i < Hook_SomeApp.UrlPartList.length; i++) {
      var eachUrlPart = Hook_SomeApp.UrlPartList[i]
      // console.log("eachUrlPart=" + eachUrlPart)
      if (urlStr.includes(eachUrlPart)) {
        console.log("urlStr " + urlStr + " includes " + eachUrlPart)
        isPrintStack = true

        // // for debug
        // isPrintStack = false
        break
      }
    }

    return isPrintStack
  }

  static HashMap_put(keyObj, valueObj){
    var isPrintStack = false

    var keyStr = keyObj.toString()
    // console.log("keyStr=" + keyStr)

    if (Hook_SomeApp.MapKeyList.includes(keyStr)){
      // console.log("keyStr=" + keyStr)

      // TODO: add valueObj filter
      isPrintStack = true
    }

    // // for debug
    // isPrintStack = true

    return isPrintStack
  }

  static HashMap_putAll(newMap){
    var isPrintStack = false

    for(var eachKey in Hook_SomeApp.MapKeyList) {
      if (newMap.containsKey(eachKey)) {
        isPrintStack = true
        break
      }
    }

    return isPrintStack
  }

  static HashMap_get(keyObj){
    // console.log("HashMap_get: keyObj=" + keyObj)
    var isPrintStack = false

    if(null != keyObj) {
      var keyStr = keyObj.toString()
      if (Hook_SomeApp.MapKeyList.includes(keyStr)){
        isPrintStack = true
      }  
    }

    return isPrintStack
  }

  static File_ctor_str(pathname){
    var isPrintStack = false

    var pathnameStr = pathname.toString()
    console.log("pathnameStr=" + pathnameStr)

    if (FridaAndroidUtil.RootBinFileList.includes(pathnameStr)){
      // console.log("found: pathnameStr=" + pathnameStr)
      isPrintStack = true
    }

    return isPrintStack
  }

  static Settings_getInt(name){
    var isMatch = false

    var nameStr = name.toString()
    console.log("nameStr=" + nameStr)

    if (Hook_SomeApp.SettingsGetIntKeyList.includes(nameStr)){
      console.log("found Settings_getInt nameStr=" + nameStr)
      isMatch = true
    }

    return isMatch
  }

  static Settings_getInt_crName(cr, name){
    return Hook_SomeApp.Settings_getInt(name)
  }

  static Settings_getInt_crNameDef(cr, name, def){
    return Hook_SomeApp.Settings_getInt(name)
  }

  static NetworkInterface_getName(name){
    var isMatch = false

    var nameStr = name.toString()
    console.log("nameStr=" + nameStr)

    if (Hook_SomeApp.NetworkInterfaceNameList.includes(nameStr)){
      console.log("found: nameStr=" + nameStr)
      isMatch = true
    }

    return isMatch
  }

  static PackageManager_getApplicationInfo(packageName){
    var isMatch = false

    var packageNameStr = packageName.toString()
    console.log("packageNameStr=" + packageNameStr)

    if (Hook_SomeApp.AppPackageNameList.includes(packageNameStr)){
      console.log("found: packageNameStr=" + packageNameStr)
      isMatch = true
    }

    return isMatch
  }

  static System_getProperty(key){
    var isMatch = false

    var keyStr = key.toString()
    // console.log("keyStr=" + keyStr)

    for (let i = 0; i < Hook_SomeApp.SystemPropertyKeyList.length; i++) {
      var eachKey = Hook_SomeApp.SystemPropertyKeyList[i]
      // console.log("eachKey=" + eachKey)
      if (keyStr.includes(eachKey)) {
        console.log("Matched: keyStr=" + keyStr + " from eachKey=" + eachKey)
        isMatch = true
        break
      }
    }

    return isMatch
  }

}


/*******************************************************************************
 * Main Hook Entry
*******************************************************************************/

class HookAppJava_SomeApp {

  static proguard_ab() {
    var clsName_proguard_ab = "com.tencent.bugly.proguard.ab"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_proguard_ab)

    var cls_proguard_ab = Java.use(clsName_proguard_ab)
    console.log("cls_proguard_ab=" + cls_proguard_ab)

    // Demo: normal function, no overload

    // public static boolean q() {
    // public static boolean com.tencent.bugly.proguard.ab.q()
    var func_proguard_ab_q = cls_proguard_ab.q
    console.log("func_proguard_ab_q=" + func_proguard_ab_q)
    if (func_proguard_ab_q) {
      func_proguard_ab_q.implementation = function () {
        var funcName = "proguard.ab.q()"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var ret_root_proguard_ab_q = this.q()
        console.log("ret_root_proguard_ab_q=" + ret_root_proguard_ab_q)

        // // do hook bypass, for: com.tencent.mm
        // ret_root_proguard_ab_q = false

        console.log("ret_root_proguard_ab_q=" + ret_root_proguard_ab_q)
        return ret_lance_a_h_a_ctxStr
      }
    }

  }

  static SimpleBodyRequest() {
    var clsName_SimpleBodyRequest = "xxx.yyy.zzz.aaa.bbb.SimpleBodyRequest"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_SimpleBodyRequest)

    var cls_SimpleBodyRequest = Java.use(clsName_SimpleBodyRequest)
    console.log("cls_SimpleBodyRequest=" + cls_SimpleBodyRequest)

    // Demo: normal function, no overload

    // public static Api newApi(Url url, RequestMethod requestMethod) {
    // public static xxx.yyy.zzz.aaa.bbb.SimpleBodyRequest$Api xxx.yyy.zzz.aaa.bbb.SimpleBodyRequest.newApi(xxx.yyy.zzz.network.Url,xxx.yyy.zzz.network.RequestMethod)
    var func_SimpleBodyRequest_newApi = cls_SimpleBodyRequest.newApi
    console.log("func_SimpleBodyRequest_newApi=" + func_SimpleBodyRequest_newApi)
    if (func_SimpleBodyRequest_newApi) {
      func_SimpleBodyRequest_newApi.implementation = function (url, requestMethod) {
        var funcName = "SimpleBodyRequest.newApi"
        var funcParaDict = {
          "url": url,
          "requestMethod": requestMethod,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var ret_api = this.newApi(url, requestMethod)
        console.log("ret_api=" + ret_api)
        return ret_api
      }
    }

    // Demo: ctor function, with overload

    // public SimpleBodyRequest(Api api) {
    // var func_SimpleBodyRequest_init = cls_SimpleBodyRequest.$init
    var func_SimpleBodyRequest_init = cls_SimpleBodyRequest.$init.overload('xxx.yyy.zzz.aaa.bbb.SimpleBodyRequest$Api')
    console.log("func_SimpleBodyRequest_init=" + func_SimpleBodyRequest_init)
    if (func_SimpleBodyRequest_init) {
      func_SimpleBodyRequest_init.implementation = function (api) {
        var funcName = "SimpleBodyRequest(api)"
        var funcParaDict = {
          "api": api
        }
        console.log("api: l=cacheMode=" + api.l.value + ", m=cacheKey=" + api.m.value + ", n=converter=" + api.n.value)
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var ret_api2 = this.$init(api)
        console.log("ret_api2=" + ret_api2)
        return ret_api2
      }
    }

  }

  static tool_ac() {
    var clsName_tool_ac = "xxx.yyy.zzz.tool.ac"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_tool_ac)

    var cls_tool_ac = Java.use(clsName_tool_ac)
    console.log("cls_tool_ac=" + cls_tool_ac)

    // Demo: normal function, with overload

    // public static String a(String str, String str2) {
    // public static java.lang.String xxx.yyy.zzz.tool.ac.a(java.lang.String,java.lang.String)
    var func_ac_a_strStr = cls_tool_ac.a.overload("java.lang.String", "java.lang.String")
    console.log("func_ac_a_strStr=" + func_ac_a_strStr)
    if (func_ac_a_strStr) {
      func_ac_a_strStr.implementation = function (str, str2) {
        var funcName = "ac.a(str,str2)"
        var funcParaDict = {
          "str": str,
          "str2": str2,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        
        var ret_strStr = this.a(str, str2)
        console.log("ret_strStr=" + ret_strStr)
        return ret_strStr
      }
    }

    // Demo: normal function, with overload, special type: "byte[]" should write as "[B"
    //    for detail of "byte[]" -> "[B", refer:
    //      https://book.crifan.org/books/reverse_debug_frida/website/common_issue/android/java_js_mapping.html

    // public static String a(String str, byte[] bArr) {
    // public static java.lang.String xxx.yyy.zzz.tool.ac.a(java.lang.String,byte[])
    var func_ac_a_strBArr = cls_tool_ac.a.overload("java.lang.String", "[B")
    console.log("func_ac_a_strBArr=" + func_ac_a_strBArr)
    if (func_ac_a_strBArr) {
      func_ac_a_strBArr.implementation = function (str, bArr) {
        var funcName = "ac.a(str,bArr)"
        var funcParaDict = {
          "str": str,
          "bArr": bArr,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        
        var ret_strBArr = this.a(str, bArr)
        console.log("ret_strBArr=" + ret_strBArr)
        return ret_strBArr
      }
    }

  }

  static b_c() {
    var clsName_b_c = "xxx.yyy.zzz.b.c"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_b_c)

    var cls_b_c = Java.use(clsName_b_c)
    console.log("cls_b_c=" + cls_b_c)

    // Demo: internal class as parameter

    // private void a(Messenger.EventsBean eventsBean, b bVar) {
    // private void xxx.yyy.zzz.b.c.a(xxx.yyy.zzz.model.Messenger$EventsBean,xxx.yyy.zzz.b.b)
    var func_b_c_a_beanBvar = cls_b_c.a.overload("xxx.yyy.zzz.model.Messenger$EventsBean", "xxx.yyy.zzz.b.b")
    console.log("func_b_c_a_beanBvar=" + func_b_c_a_beanBvar)
    if (func_b_c_a_beanBvar) {
      func_b_c_a_beanBvar.implementation = function (eventsBean, bVar) {
        var funcName = "b.c.a(eventsBean,bVar)"
        var funcParaDict = {
          "eventsBean": eventsBean,
          "bVar": bVar,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.a(eventsBean, bVar)
      }
    }

  }

  static model_d_a_a() {
    // Demo: hook internal class

    var clsName_model_d_a_a = "aaa.bbb.ccc.model.d$a$a"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_model_d_a_a)

    var cls_model_d_a_a = Java.use(clsName_model_d_a_a)
    console.log("cls_model_d_a_a=" + cls_model_d_a_a)

    // public C0030a a(boolean z3) {
    // public aaa.bbb.ccc.model.d$a$a aaa.bbb.ccc.model.d$a$a.a(boolean)
    var func_model_d_a_a_a_bool = cls_model_d_a_a.a.overload("boolean")
    console.log("func_model_d_a_a_a_bool=" + func_model_d_a_a_a_bool)
    if (func_model_d_a_a_a_bool) {
      func_model_d_a_a_a_bool.implementation = function (z3) {
        var funcName = "model.d.a.a.a(z3)"
        var funcParaDict = {
          "z3": z3,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        
        return this.a(z3)
      }
    }

  }

}

function hookNativeFunc_yourNativeFunction(libFullPath){
  console.log("hookNativeFunc_yourNativeFunction: libFullPath=" + libFullPath)
  // public native String yourNativeFunction()
  // Interceptor.attach(Module.findExportByName("yourSoLib.so", "yourNativeFunction"), {
  var func_yourNativeFunction = Module.findExportByName(libFullPath, "yourNativeFunction")
  if (null != func_yourNativeFunction) {
    Interceptor.attach(func_yourNativeFunction, {
      onEnter: function (args) {
        console.log("yourNativeFunction called")
      },
      onLeave: function (retval) {
        console.log("\t yourNativeFunction retval=" + retval)
      }
    })
  } else {
    console.error("Failed to find function " + "yourNativeFunction" + " in lib " + libFullPath)
  }

}

function hookNativeLib_yourSoLib(){
  FridaAndroidUtil.hookAfterLibLoaded("yourSoLib.so", function(libFullPath){
    FridaHookAndroidNative.JNI_OnLoad(libFullPath)

    hookNativeFunc_yourNativeFunction(libFullPath)
  })
}
function hookApp_Native(){
  FridaHookNative.hookNative_open()
  FridaHookNative.hookNative_fopen()
  FridaHookNative.hookNative_dlopen()
  // FridaHookNative.hookNative_strcpy()
  // FridaHookNative.hookNative_strncpy()
  // FridaHookNative.hookNative_strcat()

  hookNativeLib_yourSoLib()
}

function hookAppAndroidJava_common() {
  FridaHookAndroidJava.NetworkRequest_Builder()

  FridaHookAndroidJava.HashMap(Hook_SomeApp.HashMap_put, Hook_SomeApp.HashMap_putAll, Hook_SomeApp.HashMap_get)
  FridaHookAndroidJava.URL(Hook_SomeApp.URL_init)
  FridaHookAndroidJava.File(Hook_SomeApp.File_ctor_str)
  FridaHookAndroidJava.SettingsGlobal(Hook_SomeApp.Settings_getInt_crName, Hook_SomeApp.Settings_getInt_crNameDef)
  FridaHookAndroidJava.SettingsSecure(Hook_SomeApp.Settings_getInt_crName, Hook_SomeApp.Settings_getInt_crNameDef)
  FridaHookAndroidJava.NetworkInterface(Hook_SomeApp.NetworkInterface_getName)
  FridaHookAndroidJava.PackageManager(Hook_SomeApp.PackageManager_getApplicationInfo)
  FridaHookAndroidJava.System(Hook_SomeApp.System_getProperty)
  // forCrash()
}

function hookApp_AndroidJava() {
  hookAppAndroidJava_common()

  HookAppJava_SomeApp.proguard_ab()
  HookAppJava_SomeApp.SimpleBodyRequest()
  HookAppJava_SomeApp.tool_ac()
  HookAppJava_SomeApp.b_c()
  HookAppJava_SomeApp.model_d_a_a()

  // forCrash()
}

function hookInit(){
}

function hookApp() {
  hookApp_AndroidJava()
  hookApp_Native()
}

function hookAndroid() {
  console.log("FridaUtil.isAndroid()=" + FridaUtil.isAndroid())
  console.log("FridaUtil.isiOS()=" + FridaUtil.isiOS())
  // debugFroCrash()

  if(!Java.available){
    console.error("Java is not available")
    return
  }

  console.log("Java is available")
  console.log("Java.androidVersion=" + Java.androidVersion)

  Java.perform(function () {
    hookInit()

    hookApp()

    console.log("-------------------- Begin Hook --------------------")
  })

}

setImmediate(hookAndroid)
