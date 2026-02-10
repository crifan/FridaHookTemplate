/*
	File: fridaHookAndroidSomeApp.js
	Function: crifan's Frida hook some Android app related frida js template demo code
	Author: Crifan Li
	Latest: https://github.com/crifan/FridaHookTemplate/Android/frida/fridaHookAndroidSomeApp.js
	Updated: 20260210
  Usage:
   cd /Users/crifan/dev/dev_root/crifan/github/FridaHookTemplate/Android/frida
   frida -U -l fridaHookAndroidSomeApp.js -f com.app.package
   frida -U -l fridaHookAndroidSomeApp.js -p <PID>
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

// https://github.com/crifan/JsFridaUtil/blob/main/JsUtil.js
// Updated: 20251202
// pure JavaScript utils
class JsUtil {

  constructor() {
    console.log("JsUtil constructor")
  }

  static {
  }

  /*---------- Number(Int) ----------*/

  static intToHexStr(intValue, prefix="0x", isUpperCase=true){
    var fullHexStr = ""
    // console.log(`intValue: type=${typeof intValue}, val=${intValue}`)
    // if (intValue) {
    // if ((intValue == 0) || intValue) {
    if ((intValue !== null) && (intValue !== undefined) ) {
      // var hexStr = prefix + intValue.toString(16)
      // var hexStr = prefix + String(intValue).padStart(2, "0")
      // var hexStr = prefix + intValue.toString(16).padStart(2, "0")
      var intHexStr = intValue.toString(16)
      // console.log(`intValue=${intValue} -> intHexStr=${intHexStr}`)
      var padding0HexStr = intHexStr.padStart(2, "0")
      // console.log("padding0HexStr=" + padding0HexStr)
      if (isUpperCase) {
        padding0HexStr = padding0HexStr.toUpperCase()
        // console.log("padding0HexStr=" + padding0HexStr)
      }
      fullHexStr = prefix + padding0HexStr
    } else {
      // null, undefined
      fullHexStr = `${intValue}`
    }
    // console.log("fullHexStr=" + fullHexStr)
    return fullHexStr
  }

  // Convert (java) maybe negative long to unsigned long
  static toUnsignedLong(longVal) {
    var bigIntVal = BigInt(longVal)
    if (longVal < 0) {
      bigIntVal = BigInt.asUintN(64, bigIntVal)
    }
    // console.log(`bigIntVal: type=${typeof bigIntVal}, val=${bigIntVal}`)
    return bigIntVal
  }

  /*---------- Byte ----------*/

  // byte decimal to byte hex
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

  static objToStr(curObj){
    // var objJson = JSON.stringify(curObj)
    // console.log("objJson=" + objJson + ", type=" + (typeof objJson))
    var objStr = curObj.toString()
    // console.log("objStr=" + objStr + ", type=" + (typeof objStr))
    // var objTemplateStr = `${curObj}`
    // console.log("objTemplateStr=" + objTemplateStr + ", type=" + (typeof objTemplateStr))
    // var objString = String(curObj)
    // console.log("objString=" + objString + ", type=" + (typeof objString))

    return objStr
  }

  // check object whether is js string
  static isJsStr(curObj){
    // console.log("curObj=" + curObj)
    var curObjType = (typeof curObj)
    // console.log("curObjType=" + curObjType)
    var isStr = curObjType === "string"
    // console.log("isStr=" + isStr)
    return isStr
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

  static sortByKey(curList, keyName){
    if (null != curList){
      curList.sort(function(objA, objB) {
        var valueA = objA[keyName]
        var valueB = objB[keyName]
        var valudDiff = valueA - valueB
        // console.log("valueA=" + valueA + ", valueB=" + valueB + " -> valudDiff=" + valudDiff)
        return valudDiff
      })  
    }
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

// https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaUtil.js
// Updated: 20250226
// Frida Common Util
class FridaUtil {
  // for Stalker onEnter transform, is show opcode string or not
  static isShowOpcode = true

  static StringType = Object.freeze({
  // const StringType = {
    CString: "CString",
    UTF8String: "UTF8String",
    StdString: "StdString"
  })
  
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

  // Frida pointer to C++ std::string
  static ptrToStdStr(stdStrPtr){
    var realStrPtr = null
    var firstU8 = stdStrPtr.readU8()
    // console.log("firstU8=" + firstU8)
    const isTiny = (firstU8 & 1) === 0
    // console.log("isTiny=" + isTiny)
    if (isTiny) {
      realStrPtr = stdStrPtr.add(1)
    } else {
      var realStrPtrPtr = stdStrPtr.add(2 * Process.pointerSize)
      // console.log("realStrPtrPtr=" + realStrPtrPtr)
      realStrPtr = realStrPtrPtr.readPointer()
    }
    // console.log("realStrPtr=" + realStrPtr)
    var stdUtf8Str = realStrPtr.readUtf8String()  
    // console.log("stdStrPtr=" + stdStrPtr + " -> stdUtf8Str=" + stdUtf8Str)
    return stdUtf8Str
  }

  static genModuleInfoStr(foundModule){
    // console.log("Module: name=" + foundModule.name + ", base=" + foundModule.base + ", size=" + foundModule.size + ", path=" + foundModule.path)
    var endAddress = foundModule.base.add(foundModule.size)
    var sizeHexStr = JsUtil.intToHexStr(foundModule.size)
    // console.log("Module: name=" + foundModule.name + ", address=[" + foundModule.base + "-" + endAddress + "], size=" + sizeHexStr + "=" + foundModule.size + ", path=" + foundModule.path)
    var moduleInfoStr = "Module: address=[" + foundModule.base + "-" + endAddress + "], name=" + foundModule.name + ", size=" + sizeHexStr + "=" + foundModule.size + ", path=" + foundModule.path
    return moduleInfoStr
  }

  // print module basic info: name, base, size, path
  static printModuleBasicInfo(foundModule){
    var moduleInfoStr = FridaUtil.genModuleInfoStr(foundModule)
    console.log(moduleInfoStr)
  }

  // print module symbols
  static printModuleSymbols(foundModule){
    var curSymbolList = foundModule.enumerateSymbols()
    console.log("Symbol: length=" + curSymbolList.length + ", list=" + curSymbolList)
    for(var i = 0; i < curSymbolList.length; i++) {
      console.log("---------- Symbol [" + i + "]----------")
      var curSymbol = curSymbolList[i]
      var sectionStr = JSON.stringify(curSymbol.section)
      console.log("name=" + curSymbol.name + ", address=" + curSymbol.address + "isGlobal=" + curSymbol.isGlobal + ", type=" + curSymbol.type + ", section=" + sectionStr)
    }
  }

  // print module exports
  static printModuleExports(foundModule){
    var curExportList = foundModule.enumerateExports()
    console.log("Export: length=" + curExportList.length + ", list=" + curExportList)
    for(var i = 0; i < curExportList.length; i++) {
      console.log("---------- Export [" + i + "]----------")
      var curExport = curExportList[i]
      console.log("type=" + curExport.type + ", name=" + curExport.name + ", address=" + curExport.address)
    }
  }

  // print module info
  static printModuleInfo(moduleName){
    const foundModule = Module.load(moduleName)
    // const foundModule = Module.ensureInitialized()
    console.log("foundModule=" + foundModule)
  
    if (null == foundModule) {
      return
    }

    FridaUtil.printModuleBasicInfo(foundModule)

    FridaUtil.printModuleSymbols(foundModule)
    FridaUtil.printModuleExports(foundModule)
  }

  // print process basic info
  static printProcessBasicInfo(){
    console.log(
      "Process: id=" + Process.id
      + ", currentThreadId=" + Process.getCurrentThreadId()
      + ", currentDir=" + Process.getCurrentDir()
      + ", homeDir=" + Process.getHomeDir()
      + ", tmpDir=" + Process.getTmpDir()
      + ", arch=" + Process.arch
      + ", platform=" + Process.platform
      + ", pageSize=" + Process.pageSize
      + ", pointerSize=" + Process.pointerSize
      + ", codeSigningPolicy=" + Process.codeSigningPolicy
      + ", isDebuggerAttached=" + Process.isDebuggerAttached()
    )
  }

  // print all loaded modules basic info of current process
  //  Note: similar to `image list` in lldb
  static printAllLoadedModules(isSort=true){
    FridaUtil.printProcessBasicInfo()

    var moduleList = []

    Process.enumerateModules({
      onMatch: function(module){
        // console.log('Module name: ' + module.name + " - " + "Base Address: " + module.base.toString());
        // FridaUtil.printModuleBasicInfo(module)
        moduleList.push(module)
      }, 
      onComplete: function(){}
    })

    if (isSort) {
      // moduleList.sort(function(moduleA, moduleB) {
      //   // var isLarge = moduleA.base > moduleB.base
      //   // console.log("moduleA.base=" + moduleA.base + ", moduleB.base=" + moduleB.base + " -> isLarge=" + isLarge)
      //   var addrDiff = moduleA.base - moduleB.base
      //   console.log("moduleA.base=" + moduleA.base + ", moduleB.base=" + moduleB.base + " -> addrDiff=" + addrDiff)
      //   return addrDiff
      // })
      JsUtil.sortByKey(moduleList, "base")
    }

    for(var i = 0; i < moduleList.length; i++) {
      var curModule = moduleList[i]
      // var prefixStr = "\t"
      var prefixStr = "  "
      console.log(prefixStr + FridaUtil.genModuleInfoStr(curModule))
    }

  }

  static printModuleInfoAndStalkerExclude(moduleName){
    var foundModule = Process.getModuleByName(moduleName)
    console.log("moduleName=" + moduleName + " -> foundModule=" + foundModule)
    if (null != foundModule) {
      Stalker.exclude(foundModule)
      // console.log("Stalker.exclude for module:")
      // FridaUtil.printModuleBasicInfo(foundModule)
      console.log("Stalker.exclude for: " + FridaUtil.genModuleInfoStr(foundModule))
    }
  }

  // print function call and stack, output content type is: address
  static printFunctionCallStack_addr(curContext, prefix="", isPrintDelimiter=true){
    var delimiterStr = ""
    if(isPrintDelimiter){
      // JsUtil.logStr(prefix)
      delimiterStr = JsUtil.generateLineStr(prefix, true, "=", 80) + "\n"
    }

    // const linePrefix = "\n"
    // const linePrefix = "\n\t"
    const linePrefix = "\n  "
    // const linePrefix = "\n "
    var backtracerType = Backtracer.ACCURATE
    // var backtracerType = Backtracer.FUZZY
    var stackStr = Thread.backtrace(curContext, backtracerType).map(DebugSymbol.fromAddress).join(linePrefix)

    var prefixStr = prefix
    if (!JsUtil.strIsEmpty(prefix)){
      prefixStr = prefix + " "
    }
    prefixStr = prefixStr + 'addr Stack:' + linePrefix

    var endStr = "\n"

    var fullStr = delimiterStr + prefixStr + stackStr + endStr

    console.log(fullStr)
  }

  // static dumpMemory(toDumpPtr, byteLen=128){
  static dumpMemory(toDumpPtr, prefixStr="", byteLen=128){
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

    if (JsUtil.strIsEmpty(prefixStr)){
      prefixStr = `[${toDumpPtr}] `
    } else {
      prefixStr = prefixStr + " "
    }

    console.log(prefixStr + "Dump Memory:\n" + dumpHexStr)
  }

  // convert ByteArray to Opcode string
  static byteArrayToOpcodeStr(byteArr){
    var byteStrList = []
    for(var i = 0; i < byteArr.length; i++) {
      var curByte = byteArr[i]
      // console.log("curByte=" + curByte)
      var curByteStr = JsUtil.intToHexStr(curByte, "", true)
      // console.log("curByteStr=" + curByteStr)
      byteStrList.push(curByteStr)
    }
    // console.log("byteStrList=" + byteStrList)
    var opcodeStr = byteStrList.join(" ")
    // console.log("byteArr=" + byteArr + " -> opcodeStr=" + opcodeStr)
    return opcodeStr
  }

  // read byte array from address
  // Note: curAddress is NativePointer
  static readAddressByteArray(curAddress, byteSize){
    // console.log("curAddress=" + curAddress + ", byteSize=" + byteSize)
    // var instructionByteArrBuffer = curAddress.readByteArray(byteSize)
    var curByteArray = []
    for(var i = 0; i < byteSize; i++){
      var curAddr = curAddress.add(i)
      // console.log("curAddr=" + curAddr)
      var byteU8 = curAddr.readU8()
      // console.log("byteU8=" + byteU8)
      curByteArray.push(byteU8)
    }
    // console.log("curByteArray=" + curByteArray)
    return curByteArray
  }

  static genInstructionOpcodeStr(instruction){
    var instructionByteArr = FridaUtil.readAddressByteArray(instruction.address, instruction.size)
    // console.log("instructionByteArr=" + instructionByteArr)

    // var instructionOpcodeStr = hexdump(
    //   instructionByteArr,
    //   {
    //     offset: 0, 
    //     length: curInstructionSize,
    //     header: false,
    //     ansi: false
    //   }
    // )
    var instructionOpcodeStr = FridaUtil.byteArrayToOpcodeStr(instructionByteArr)
    // console.log("instructionOpcodeStr=" + instructionOpcodeStr)
    return instructionOpcodeStr
  }

  static printInstructionInfo(instruction){
    // Instruction: address=0x252c0edf8,toString()=br x10,next=0x4,size=4,mnemonic=br,opStr=x10,operands=[{"type":"reg","value":"x10","access":"r"}],regsAccessed={"read":["x10"],"written":[]},regsRead=[],regsWritten=[],groups=["jump"],toJSON()={"address":"0x252c0edf8","next":"0x4","size":4,"mnemonic":"br","opStr":"x10","operands":[{"type":"reg","value":"x10","access":"r"}],"regsAccessed":{"read":["x10"],"written":[]},"regsRead":[],"regsWritten":[],"groups":["jump"]}
    console.log("Instruction: address=" + instruction.address
      + ",toString()=" + instruction.toString()
      + ",toJSON()=" + JSON.stringify(instruction.toJSON())
      // + ",next=" + instruction.next
      // + ",size=" + instruction.size
      // + ",mnemonic=" + instruction.mnemonic
      // + ",opStr=" + instruction.opStr
      // + ",operands=" + JSON.stringify(instruction.operands)
      // + ",regsAccessed=" + JSON.stringify(instruction.regsAccessed)
      // + ",regsRead=" + JSON.stringify(instruction.regsRead)
      // + ",regsWritten=" + JSON.stringify(instruction.regsWritten)
      // + ",groups=" + JSON.stringify(instruction.groups)
    )
  }

  // Frida Stalker hoo unknown name native function
  static stalkerHookUnnameNative(moduleBaseAddress, funcRelativeStartAddr, functionSize, argNum, hookFuncMap){
    console.log("Frida Stalker hook: module: baseAddress=" + moduleBaseAddress + ", isShowOpcode=" + FridaUtil.isShowOpcode)

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
                  // FridaUtil.printInstructionInfo(instruction)

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
                  // console.log("\t" + curRealAddr + " <+" + curOffsetInt + ">: " + instructionStr)

                  var opcodeStr = ""
                  if (FridaUtil.isShowOpcode) {
                    opcodeStr = " " + FridaUtil.genInstructionOpcodeStr(instruction)
                  }
                  var instructionFullLogStr = "\t" + curRealAddr + " <+" + curOffsetInt + ">" + opcodeStr + ": " + instructionStr
                  console.log(instructionFullLogStr)
                  // 0x252c0edf8 <+356>: br x10
                  // 0x252c0edf8 <+356> 40 01 1F D6: br x10

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

// https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaAndroidUtil.js
// Updated: 20251209
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

  // const
  static clsName_Long                         = "java.lang.Long"

  static clsName_ByteArrayOutputStream        = "java.io.ByteArrayOutputStream"
  static clsName_FileNotFoundException        = "java.io.FileNotFoundException"
  static clsName_File                         = "java.io.File"

  static clsName_HttpURLConnection            = "java.net.HttpURLConnection"
  static clsName_URLConnection                = "java.net.URLConnection"
  static clsName_HttpsURLConnection           = "javax.net.ssl.HttpsURLConnection"

  static clsName_SharedPreferencesImpl_EditorImpl = "android.app.SharedPreferencesImpl$EditorImpl"
  static clsName_MemoryInfo                   = "android.app.ActivityManager.MemoryInfo"

  static clsName_ConfigurationInfo            = "android.content.pm.ConfigurationInfo"
  static clsName_Configuration                = "android.content.res.Configuration"
  static clsName_FeatureInfo                  = "android.content.pm.FeatureInfo"

  static clsName_Message                      = "android.os.Message"
  static clsName_Messenger                    = "android.os.Messenger"
  static clsName_Parcel                       = "android.os.Parcel"

  static clsName_DisplayMetrics               = "android.util.DisplayMetrics"

  static clsName_Buffer                       = "com.android.okhttp.okio.Buffer"
  static clsName_RetryableSink                = "com.android.okhttp.internal.http.RetryableSink"
  static clsName_HttpURLConnectionImpl        = "com.android.okhttp.internal.huc.HttpURLConnectionImpl"
  static clsName_DelegatingHttpsURLConnection = "com.android.okhttp.internal.huc.DelegatingHttpsURLConnection"
  static clsName_HttpsURLConnectionImpl       = "com.android.okhttp.internal.huc.HttpsURLConnectionImpl"
  // static clsName_Headers_Builder              = "com.android.okhttp.internal.huc.Headers$Builder"
  static clsName_Headers_Builder              = "com.android.okhttp.Headers$Builder"

  static clsName_CronetUrlRequest             = "org.chromium.net.impl.CronetUrlRequest"


  // {env: {clazz: className} }
  static cacheDictEnvClazz = {}

  static curThrowableCls = null

  static JavaArray = null
  static JavaArrays = null
  static JavaArrayList = null

  static JavaByteArr = null
  static JavaObjArr = null

  static StandardCharsets = null
  static ByteArrayOutputStream = null
  static FileNotFoundException = null
  static Long = null
  static Long_0 = null

  // https://source.android.com/docs/core/runtime/dex-format?hl=zh-cn
  // https://cmrodriguez.me/blog/methods/
  static FridaDexTypeMapppingDict = {
    "void":     "V",

    "boolean":  "Z",
    "char":     "C",
    "byte":     "B",
    "short":    "S",
    "int":      "I",
    "long":     "J",
    "float":    "F",
    "double":   "D",

    // from FridaDexTypeMapppingDict_list

    // TODO: add more type
  }

  static FridaDexTypeMapppingDict_list = {
    "char[]":   "[C",
    "byte[]":   "[B",
    "short[]":  "[S",
    "int[]":    "[I",
    "long[]":   "[J",
    "float[]":  "[F",
    "double[]": "[D",

    "String[]": "[Ljava/lang/String;",
    "Object[]": "[Ljava/lang/Object;",
  }

  constructor() {
    console.log("FridaAndroidUtil constructor")
  }

  static {
    Object.assign(FridaAndroidUtil.FridaDexTypeMapppingDict, FridaAndroidUtil.FridaDexTypeMapppingDict_list)

    if (FridaUtil.isAndroid()) {
      console.log("FridaAndroidUtil.FridaDexTypeMapppingDict_list=" + FridaAndroidUtil.FridaDexTypeMapppingDict_list)
      console.log("FridaAndroidUtil.FridaDexTypeMapppingDict=" + FridaAndroidUtil.FridaDexTypeMapppingDict)

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
      
      FridaAndroidUtil.StandardCharsets = Java.use("java.nio.charset.StandardCharsets")
      console.log("FridaAndroidUtil.StandardCharsets=" + FridaAndroidUtil.StandardCharsets)

      FridaAndroidUtil.ByteArrayOutputStream = Java.use(FridaAndroidUtil.clsName_ByteArrayOutputStream)
      console.log("FridaAndroidUtil.ByteArrayOutputStream=" + FridaAndroidUtil.ByteArrayOutputStream)

      FridaAndroidUtil.FileNotFoundException = Java.use(FridaAndroidUtil.clsName_FileNotFoundException)
      console.log("FridaAndroidUtil.FileNotFoundException=" + FridaAndroidUtil.FileNotFoundException)

      FridaAndroidUtil.Long = Java.use(FridaAndroidUtil.clsName_Long)
      console.log("FridaAndroidUtil.Long=" + FridaAndroidUtil.Long)
      // FridaAndroidUtil.Long_0 = FridaAndroidUtil.Long.valueOf(0)
      // FridaAndroidUtil.Long_0 = FridaAndroidUtil.Long.$new(0)
      // FridaAndroidUtil.Long_0 = int64(0)
      FridaAndroidUtil.Long_0 = 0
      console.log("FridaAndroidUtil.Long_0=" + FridaAndroidUtil.Long_0)

    } else {
      console.warn("FridaAndroidUtil: Non Android platfrom, no need init Android related")
    }
  }

  /*-------------------- byte[] --------------------*/

  // convert (Java) byte[] to hex string
  static bytesToHexStr(curBytes, separator=",", hasBracket=true, has0xPrefix=false, isUpperCase=true, isAddLenPrefix=true){
    var retAllHexStr = ""
    if(curBytes) {
      var hexStrList = []
      var byteLen = curBytes.length
      // console.log(`byteLen=${byteLen}`)
      for(var i = 0; i < curBytes.length; i++) {
        var curByte = curBytes[i]
        // console.log(`curByte=${curByte}`)
        var positiveByte = curByte
        if (positiveByte < 0) {
          // convert to positive byte, eg: -104 => 152
          positiveByte = positiveByte + 256
        }
        // console.log(`positiveByte=${positiveByte}`)
        var prefixStr = ""
        if (has0xPrefix) {
          prefixStr = "0x"
        }
        var byteHexStr = JsUtil.intToHexStr(positiveByte, prefixStr, isUpperCase)
        // console.log(`byteHexStr=${byteHexStr}`)
        hexStrList.push(byteHexStr)
      }
      retAllHexStr = hexStrList.join(separator)
      if (hasBracket) {
        retAllHexStr = `[${retAllHexStr}]`
      }

      if(isAddLenPrefix) {
        retAllHexStr = `<len=${byteLen}>${retAllHexStr}`
      }
    }

    return retAllHexStr
  }

  /*-------------------- Long --------------------*/

  // print/convet Java long (maybe negtive) to (unsigned=positive long value) string
  static longToStr(longVal){
    var longStr = FridaAndroidUtil.Long.toUnsignedString(longVal)
    // console.log(`longStr: type=${typeof longStr}, val=${longStr}`)
    return longStr
  }

  /*-------------------- isClass --------------------*/

  static isClass_File(curObj){
    var isClsFile = FridaAndroidUtil.isJavaClass(curObj, FridaAndroidUtil.clsName_File)
    console.log("curObj=" + curObj + " -> isClsFile=" + isClsFile)
    return isClsFile
  }

  static isClass_HttpURLConnection(curObj){
    var isClsHttpURLConnection = FridaAndroidUtil.isJavaClass(curObj, FridaAndroidUtil.clsName_HttpURLConnection)
    console.log("curObj=" + curObj + " -> isClsHttpURLConnection=" + isClsHttpURLConnection)
    return isClsHttpURLConnection
  }

  static isClass_URLConnection(curObj){
    var isClsURLConnection = FridaAndroidUtil.isJavaClass(curObj, FridaAndroidUtil.clsName_URLConnection)
    console.log("curObj=" + curObj + " -> isClsURLConnection=" + isClsURLConnection)
    return isClsURLConnection
  }

  static isClass_HttpsURLConnection(curObj){
    var isClsHttpsURLConnection = FridaAndroidUtil.isJavaClass(curObj, FridaAndroidUtil.clsName_HttpsURLConnection)
    console.log("curObj=" + curObj + " -> isClsHttpsURLConnection=" + isClsHttpsURLConnection)
    return isClsHttpsURLConnection
  }

  static isClass_HttpURLConnectionImpl(curObj){
    var isClsHttpURLConnectionImpl = FridaAndroidUtil.isJavaClass(curObj, FridaAndroidUtil.clsName_HttpURLConnectionImpl)
    console.log("curObj=" + curObj + " -> isClsHttpURLConnectionImpl=" + isClsHttpURLConnectionImpl)
    return isClsHttpURLConnectionImpl
  }

  static isClass_DelegatingHttpsURLConnection(curObj){
    var isClsDelegatingHttpsURLConnection = FridaAndroidUtil.isJavaClass(curObj, FridaAndroidUtil.clsName_DelegatingHttpsURLConnection)
    console.log("curObj=" + curObj + " -> isClsDelegatingHttpsURLConnection=" + isClsDelegatingHttpsURLConnection)
    return isClsDelegatingHttpsURLConnection
  }

  static isClass_HttpsURLConnectionImpl(curObj){
    var isClsHttpsURLConnectionImpl = FridaAndroidUtil.isJavaClass(curObj, FridaAndroidUtil.clsName_HttpsURLConnectionImpl)
    console.log("curObj=" + curObj + " -> isClsHttpsURLConnectionImpl=" + isClsHttpsURLConnectionImpl)
    return isClsHttpsURLConnectionImpl
  }

  /*-------------------- printClass --------------------*/

  static printClassTemplate(className, inputObj, callback_printProps, prefixStr="", fullClassName=""){
    // console.log(`printClassTemplate: className=${className}, inputObj=${inputObj}, callback_printProps=${callback_printProps}, prefixStr=${prefixStr}, fullClassName=${fullClassName}`)
    const PrintFuncName = "printClass_" + className
    const NewPref = prefixStr ? (prefixStr + " ") : prefixStr
    const PrefAndClassName = `${PrintFuncName}: ${NewPref}${className}`
    if (inputObj) {
      if (!fullClassName) {
        fullClassName = className
      }
      // console.log(`${PrefAndClassName}: fullClassName=${fullClassName}`)
      if (FridaAndroidUtil.isJavaClass(inputObj, fullClassName)) {
        var realClassName = FridaAndroidUtil.getJavaClassName(inputObj)
        // console.log(`${PrefAndClassName}: realClassName=${realClassName}`)
        var curObj = FridaAndroidUtil.castToJavaClass(inputObj, fullClassName)
        // console.log(`${PrefAndClassName}: curObj=${curObj}`)
        var curClsNameValStr = FridaAndroidUtil.valueToNameStr(curObj)
        var fullPrefix = `${PrefAndClassName}:${curClsNameValStr}:`
        var strInfoDict = {
          "className": className,
          "fullClassName": fullClassName,
          "realClassName": realClassName,
          "printFuncName": PrintFuncName,
          "origPref": prefixStr,
          "newPref": NewPref,
          "prefAndClassName": PrefAndClassName,
          "fullPref": fullPrefix,
          "curClsNameVal": curClsNameValStr,
        }
        callback_printProps(curObj, strInfoDict)
      } else {
        console.warn(`${PrefAndClassName}: ${FridaAndroidUtil.valueToNameStr(inputObj)} not a ${fullClassName}`)
      }
    } else {
      console.log(`${PrefAndClassName}: null`)
    }
  }

  static printClass_SharedPreferencesImpl_EditorImpl(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "SharedPreferencesImpl$EditorImpl",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // android.app.SharedPreferencesImpl$EditorImpl
        // https://android.googlesource.com/platform/frameworks/base.git/+/master/core/java/android/app/SharedPreferencesImpl.java

        console.log(fullPref
          + " mEditorLock=" + curObj.mEditorLock.value
          + ", mModified=" + FridaAndroidUtil.mapToStr(curObj.mModified.value)
          + ", mClear=" + curObj.mClear.value
        )
      },
      prefixStr,
      FridaAndroidUtil.clsName_SharedPreferencesImpl_EditorImpl
    )
  }

  static printClass_CronetUrlRequest(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "CronetUrlRequest",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // org.chromium.net.impl.CronetUrlRequest
        // https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/cronet/android/java/src/org/chromium/net/impl/CronetUrlRequest.java

        console.log(fullPref
          + " mInitialUrl=" + curObj.mInitialUrl.value
          + " mInitialMethod=" + curObj.mInitialMethod.value
          + " mRequestHeaders=" + curObj.mRequestHeaders.value
          + " mUploadDataStream=" + curObj.mUploadDataStream.value
          + " mRequestContext=" + curObj.mRequestContext.value
          + " mNetworkHandle=" + curObj.mNetworkHandle.value
          + " mPriority=" + curObj.mPriority.value
          + " mStarted=" + curObj.mStarted.value
          + " mDisableCache=" + curObj.mDisableCache.value
        )
      },
      prefixStr,
      FridaAndroidUtil.clsName_CronetUrlRequest
    )
  }

  static printClass_Messenger(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "Messenger",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // android.os.Messenger
        // https://developer.android.com/reference/android/os/Messenger

        console.log(fullPref
          + " CREATOR=" + curObj.CREATOR.value
          + ", binder=" + binder
        )
      },
      prefixStr,
      FridaAndroidUtil.clsName_Messenger
    )
  }

  static printClass_Message(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "Message",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // android.os.Message
        // https://developer.android.com/reference/android/os/Message

        var callback = curObj.getCallback()
        var dataBundle = curObj.getData()
        var targetHandler = curObj.getTarget()
        var when = curObj.getWhen()
        var isAsync = curObj.isAsynchronous()

        var replyToVal = curObj.replyTo.value

        console.log(fullPref
          + " arg1=" + curObj.arg1.value
          + ", arg2=" + curObj.arg2.value
          + ", obj=" + curObj.obj.value
          + ", replyTo=" + replyToVal
          + ", sendingUid=" + curObj.sendingUid.value
          + ", what=" + curObj.what.value

          + ", callback=" + callback
          + ", dataBundle=" + dataBundle
          + ", targetHandler=" + targetHandler
          + ", when=" + when
          + ", isAsync=" + isAsync
        )

        FridaAndroidUtil.printClass_Messenger(replyToVal, `${origPref} `)
      },
      prefixStr,
      FridaAndroidUtil.clsName_Messenger
    )
  }

  static printClass_URLConnection(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "URLConnection",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // java.net.URLConnection
        // https://cs.android.com/android/platform/superproject/main/+/main:libcore/ojluni/src/main/java/java/net/URLConnection.java;drc=bd205f23c74d7498c9958d2bfa8622aacfe59517;l=161

        // console.log("URLConnection:"
        //   + " url=" + curObj.url.value
        //   + ", connected=" + curObj.connected.value
        //   + ", doInput=" + curObj.doInput.value
        //   + ", doOutput=" + curObj.doOutput.value
        //   + ", allowUserInteraction=" + curObj.allowUserInteraction.value
        //   + ", useCaches=" + curObj.useCaches.value
        //   + ", ifModifiedSince=" + curObj.ifModifiedSince.value
        //   + ", defaultAllowUserInteraction=" + curObj.defaultAllowUserInteraction.value
        //   + ", defaultUseCaches=" + curObj.defaultUseCaches.value
        //   + ", connectTimeout=" + curObj.connectTimeout.value
        //   + ", readTimeout=" + curObj.readTimeout.value
        //   + ", requests=" + curObj.requests.value
        //   + ", fileNameMap=" + curObj.fileNameMap.value
        // )

        var url = curObj.getURL()
        // console.log("url=" + url)
        var doInput = curObj.getDoInput()
        // console.log("doInput=" + doInput)
        var doOutput = curObj.getDoOutput()
        // console.log("doOutput=" + doOutput)
        var allowUserInteraction = curObj.getAllowUserInteraction()
        // console.log("allowUserInteraction=" + allowUserInteraction)
        var useCaches = curObj.getUseCaches()
        // console.log("useCaches=" + useCaches)
        var ifModifiedSince = curObj.getIfModifiedSince()
        // console.log("ifModifiedSince=" + ifModifiedSince)
        
        var requestHeaderMap = curObj.getRequestProperties() // this is request headers
        // console.log("requestHeaderMap=" + requestHeaderMap)
        var requestHeadersStr = FridaAndroidUtil.mapToStr(requestHeaderMap)
        // console.log("requestHeadersStr=" + requestHeadersStr)

        // // all following field is: response fields, NOT request fields
        // var respHeaders_contentLength = curObj.getContentLength()
        // console.log("respHeaders_contentLength=" + respHeaders_contentLength)
        // var respHeaders_contentLengthLong = curObj.getContentLengthLong()
        // console.log("respHeaders_contentLengthLong=" + respHeaders_contentLengthLong)
        // var respHeaders_contentType = curObj.getContentType()
        // console.log("respHeaders_contentType=" + respHeaders_contentType)
        // var respHeaders_contentEncoding = curObj.getContentEncoding()
        // console.log("respHeaders_contentEncoding=" + respHeaders_contentEncoding)
        // var respHeaders_date = curObj.getDate()
        // console.log("respHeaders_date=" + respHeaders_date)
        // var respHeaders_lastModified = curObj.getLastModified()
        // console.log("respHeaders_lastModified=" + respHeaders_lastModified)

        var defaultAllowUserInteraction = curObj.getDefaultAllowUserInteraction()
        // console.log("defaultAllowUserInteraction=" + defaultAllowUserInteraction)
        var defaultUseCaches = curObj.getDefaultUseCaches()
        // console.log("defaultUseCaches=" + defaultUseCaches)
        var connectTimeout = curObj.getConnectTimeout()
        // console.log("connectTimeout=" + connectTimeout)
        var readTimeout = curObj.getReadTimeout()
        // console.log("readTimeout=" + readTimeout)
        var fileNameMap = curObj.getFileNameMap()
        // console.log("fileNameMap=" + fileNameMap)
        // var fileNameMapStr = FridaAndroidUtil.mapToStr(fileNameMap)
        // console.log("fileNameMapStr=" + fileNameMapStr)

        console.log(fullPref
          + " url=" + url
          + ", doInput=" + doInput
          + ", doOutput=" + doOutput
          + ", allowUserInteraction=" + allowUserInteraction
          + ", useCaches=" + useCaches
          + ", ifModifiedSince=" + ifModifiedSince
          + ", requestHeadersStr=" + requestHeadersStr

          // // response headers
          // + ", respHeaders_contentLength=" + respHeaders_contentLength
          // + ", respHeaders_contentLengthLong=" + respHeaders_contentLengthLong
          // + ", respHeaders_contentType=" + respHeaders_contentType
          // + ", respHeaders_contentEncoding=" + respHeaders_contentEncoding
          // + ", respHeaders_date=" + respHeaders_date
          // + ", respHeaders_lastModified=" + respHeaders_lastModified

          + ", defaultAllowUserInteraction=" + defaultAllowUserInteraction
          + ", defaultUseCaches=" + defaultUseCaches
          + ", connectTimeout=" + connectTimeout
          + ", readTimeout=" + readTimeout
          + ", fileNameMap=" + fileNameMap
        )
      },
      prefixStr,
      FridaAndroidUtil.clsName_URLConnection
    )
  }

  static printClass_HttpURLConnection(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "HttpURLConnection",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // java.net.HttpURLConnection

        // var headerFields = curObj.getHeaderFields()
        // console.log("HttpURLConnection: headerFields=" + headerFields)
        // var reqMethod = curObj.getRequestMethod()
        // console.log("HttpURLConnection: reqMethod=" + reqMethod)

        // console.log("HttpURLConnection:"
        //   + "  method=" + curObj.method.value
        //   + ", chunkLength=" + curObj.chunkLength.value
        //   + ", fixedContentLength=" + curObj.fixedContentLength.value
        //   + ", fixedContentLengthLong=" + curObj.fixedContentLengthLong.value
        //   + ", responseCode=" + curObj.responseCode.value
        //   + ", responseMessage=" + curObj.responseMessage.value
        //   + ", instanceFollowRedirects=" + curObj.instanceFollowRedirects.value
        //   + ", followRedirects=" + curObj.followRedirects.value
        // )

        console.log(fullPref
          + " method=" + curObj.getRequestMethod()
          // + ", responseCode=" + curObj.getResponseCode() // NOTE: will trigger send request !
          // + ", responseMessage=" + curObj.getResponseMessage()  // NOTE: will trigger send request !
          + ", instanceFollowRedirects=" + curObj.getInstanceFollowRedirects()
          + ", followRedirects=" + curObj.getFollowRedirects()
        )
      },
      prefixStr,
      FridaAndroidUtil.clsName_HttpURLConnection
    )
  }

  static printClass_HttpsURLConnection(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "HttpsURLConnection",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // javax.net.ssl.HttpsURLConnection

        console.log(fullPref
          + " no fields"
        )

        var httpURLConnectionObj = FridaAndroidUtil.castToJavaClass(curObj, FridaAndroidUtil.clsName_HttpURLConnection)
        FridaAndroidUtil.printClass_HttpURLConnection(httpURLConnectionObj, `${origPref} `)
      },
      prefixStr,
      FridaAndroidUtil.clsName_HttpsURLConnection
    )
  }

  static printClass_DelegatingHttpsURLConnection(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "DelegatingHttpsURLConnection",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // com.android.okhttp.internal.huc.DelegatingHttpsURLConnection

        console.log(fullPref
          + "  delegate=" + curObj.delegate.value
        )

        var httpsURLConnectionObj = FridaAndroidUtil.castToJavaClass(curObj, FridaAndroidUtil.clsName_HttpsURLConnection)
        FridaAndroidUtil.printClass_HttpsURLConnection(httpsURLConnectionObj, `${origPref} `)
      },
      prefixStr,
      FridaAndroidUtil.clsName_DelegatingHttpsURLConnection
    )
  }

  static printClass_HttpsURLConnectionImpl(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "HttpsURLConnectionImpl",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // com.android.okhttp.internal.huc.HttpsURLConnectionImpl

        console.log(fullPref
          + "  delegate=" + curObj.delegate.value
        )

        var delegatingHttpsURLConnectionObj = FridaAndroidUtil.castToJavaClass(curObj, FridaAndroidUtil.clsName_DelegatingHttpsURLConnection)
        FridaAndroidUtil.printClass_DelegatingHttpsURLConnection(delegatingHttpsURLConnectionObj, `${origPref} `)
      },
      prefixStr,
      FridaAndroidUtil.clsName_HttpsURLConnectionImpl
    )
  }

  static printClass_HttpURLConnectionImpl(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "HttpURLConnectionImpl",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // com.android.okhttp.internal.huc.HttpURLConnectionImpl

        // var reqHeadersStr = FridaAndroidUtil.printClass_Headers_Builder(curObj.requestHeaders.value)
        var reqHeadersStr = FridaAndroidUtil.HeadersBuilderToString(curObj.requestHeaders.value)
        // console.log("reqHeadersStr=" + reqHeadersStr)

        console.log(fullPref
          + "  client=" + curObj.client.value
          + ", requestHeaders=" + reqHeadersStr
          + ", fixedContentLength=" + curObj.fixedContentLength.value
          + ", followUpCount=" + curObj.followUpCount.value
          + ", httpEngineFailure=" + curObj.httpEngineFailure.value
          + ", httpEngine=" + curObj.httpEngine.value
          + ", responseHeaders=" + curObj.responseHeaders.value
          + ", route=" + curObj.route.value
          + ", handshake=" + curObj.handshake.value
          + ", urlFilter=" + curObj.urlFilter.value
        )

        var httpURLConnectionObj = FridaAndroidUtil.castToJavaClass(curObj, FridaAndroidUtil.clsName_HttpURLConnection)
        FridaAndroidUtil.printClass_HttpURLConnection(httpURLConnectionObj, `${origPref} `)
      },
      prefixStr,
      FridaAndroidUtil.clsName_HttpURLConnectionImpl
    )
  }

  // HTTP:  com.android.okhttp.internal.huc.HttpURLConnectionImpl
  // HTTPS: com.android.okhttp.internal.huc.HttpsURLConnectionImpl
  static printClass_HttpOrHttpsURLConnectionImpl(curObj){
    if (FridaAndroidUtil.isClass_HttpURLConnectionImpl(curObj)){
      FridaAndroidUtil.printClass_HttpURLConnectionImpl(curObj)
    } else if (FridaAndroidUtil.isClass_HttpsURLConnectionImpl(curObj)){
      FridaAndroidUtil.printClass_HttpsURLConnectionImpl(curObj)
    } else {
      var curClsName = FridaAndroidUtil.getJavaClassName(curObj)
      console.log("curClsName=" + curClsName)

      console.log("Unrecognized URLConnectionImpl class: " + curObj + ", curClsName=" + curClsName)
    }
  }

  static printClass_RetryableSink(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "RetryableSink",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // com.android.okhttp.internal.http.RetryableSink
        // https://cs.android.com/android/platform/superproject/+/master:external/okhttp/repackaged/okhttp/src/main/java/com/android/okhttp/internal/http/RetryableSink.java
        // https://android.googlesource.com/platform/external/okhttp/+/refs/heads/main/okhttp/src/main/java/com/squareup/okhttp/internal/http/RetryableSink.java

        var contentVar = curObj.content.value

        console.log(fullPref
          + " closed=" + curObj.closed.value
          + ", limit=" + curObj.limit.value
          + ", contentLength()=" + curObj.contentLength()
          + ", content=" + contentVar
        )

        FridaAndroidUtil.printClass_Buffer(contentVar, `${origPref} `)
      },
      prefixStr,
      FridaAndroidUtil.clsName_RetryableSink
    )
  }

  static printClass_File(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "File",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // https://developer.android.com/reference/java/io/File

        console.log(fullPref
          + " separator=" + curObj.separator.value
          + ", pathSeparator=" + curObj.pathSeparator.value
          + ", exists=" + curObj.exists()
          + ", name=" + curObj.getName()
          + ", absPath=" + curObj.getAbsolutePath()
        )
      },
      prefixStr,
      FridaAndroidUtil.clsName_File
    )
  }

  static printClass_Buffer(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "Buffer",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // com.android.okhttp.okio.Buffer
        // https://android.googlesource.com/platform/external/okhttp/+/refs/heads/main/okio/okio/src/main/java/okio/Buffer.java
  
        var byteArray = curObj.readByteArray()

        console.log(fullPref
          // + " size=" + curObj.size.value
          + " size=" + curObj._size.value
          + ", head=" + curObj.head.value
          + ", toString()=" + curObj.toString()
          + ", byteArray=" + byteArray
        )
      },
      prefixStr,
      FridaAndroidUtil.clsName_Buffer
    )
  }

  static printClass_DisplayMetrics(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "DisplayMetrics",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // android.util.DisplayMetrics
        // https://developer.android.com/reference/android/util/DisplayMetrics#DisplayMetrics()

        console.log(fullPref
          + " DENSITY_DEVICE_STABLE=" + curObj.DENSITY_DEVICE_STABLE.value
          + ", density=" + curObj.density.value
          + ", densityDpi=" + curObj.densityDpi.value
          + ", heightPixels=" + curObj.heightPixels.value
          + ", scaledDensity=" + curObj.scaledDensity.value
          + ", widthPixels=" + curObj.widthPixels.value
          + ", xdpi=" + curObj.xdpi.value
          + ", ydpi=" + curObj.ydpi.value
        )
      },
      prefixStr,
      FridaAndroidUtil.clsName_DisplayMetrics
    )
  }

  static printClass_ConfigurationInfo(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "ConfigurationInfo",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // android.content.pm.ConfigurationInfo
        // https://developer.android.com/reference/android/content/pm/ConfigurationInfo#INPUT_FEATURE_FIVE_WAY_NAV

        console.log(fullPref
          + " reqGlEsVersion=" + curObj.reqGlEsVersion.value
          + ", reqInputFeatures=" + curObj.reqInputFeatures.value
          + ", reqKeyboardType=" + curObj.reqKeyboardType.value
          + ", reqNavigation=" + curObj.reqNavigation.value
          + ", reqTouchScreen=" + curObj.reqTouchScreen.value
        )
      },
      prefixStr,
      FridaAndroidUtil.clsName_ConfigurationInfo
    )
  }

  static printClass_Configuration(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "ConfigurationInfo",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // android.content.res.Configuration
        // https://developer.android.com/reference/android/content/res/Configuration#screenLayout

        console.log(fullPref
          + " colorMode=" + curObj.colorMode.value
          + ", densityDpi=" + curObj.densityDpi.value
          + ", fontScale=" + curObj.fontScale.value
          + ", fontWeightAdjustment=" + curObj.fontWeightAdjustment.value
          + ", hardKeyboardHidden=" + curObj.hardKeyboardHidden.value
          + ", keyboard=" + curObj.keyboard.value
          + ", keyboardHidden=" + curObj.keyboardHidden.value
          + ", locale=" + curObj.locale.value
          + ", mcc=" + curObj.mcc.value
          + ", mnc=" + curObj.mnc.value
          + ", navigation=" + curObj.navigation.value
          + ", navigationHidden=" + curObj.navigationHidden.value
          + ", orientation=" + curObj.orientation.value
          + ", screenHeightDp=" + curObj.screenHeightDp.value
          + ", screenLayout=" + curObj.screenLayout.value
          + ", screenWidthDp=" + curObj.screenWidthDp.value
          + ", smallestScreenWidthDp=" + curObj.smallestScreenWidthDp.value
          + ", touchscreen=" + curObj.touchscreen.value
          + ", uiMode=" + curObj.uiMode.value
        )
      },
      prefixStr,
      FridaAndroidUtil.clsName_Configuration
    )
  }

  static printClass_FeatureInfo(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "FeatureInfo",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // android.content.pm.FeatureInfo
        // https://developer.android.com/reference/android/content/pm/FeatureInfo

        console.log(fullPref
          + " flags=" + curObj.flags.value
          + ", name=" + curObj.name.value
          + ", reqGlEsVersion=" + curObj.reqGlEsVersion.value
          + ", version=" + curObj.version.value
        )
      },
      prefixStr,
      FridaAndroidUtil.clsName_FeatureInfo
    )
  }

  static printClass_ActivityManagerMemoryInfo(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "MemoryInfo",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // android.app.ActivityManager.MemoryInfo
        // https://developer.android.com/reference/android/app/ActivityManager.MemoryInfo

        console.log(fullPref
          + " CREATOR=" + curObj.CREATOR.value
          + ", advertisedMem=" + curObj.advertisedMem.value
          + ", availMem=" + curObj.availMem.value
          + ", lowMemory=" + curObj.lowMemory.value
          + ", threshold=" + curObj.threshold.value
          + ", totalMem=" + curObj.totalMem.value
        )
      },
      prefixStr,
      FridaAndroidUtil.clsName_MemoryInfo
    )
  }

  static printClass_Parcel(inputObj, prefixStr=""){
    FridaAndroidUtil.printClassTemplate(
      "Parcel",
      inputObj,
      function (curObj, strInfoDict) {
        var fullPref = strInfoDict["fullPref"]
        var origPref = strInfoDict["origPref"]
        // android.os.Parcel
        // https://developer.android.com/reference/android/os/Parcel

        var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)

        var stringCreatorValue = curObj.STRING_CREATOR.value
        var stringCreatorStr = FridaAndroidUtil.valueToNameStr(stringCreatorValue)

        var dataSize = curObj.dataSize()
        var dataPosition = curObj.dataPosition()
        var dataAvail = curObj.dataAvail()
        var dataCapacity = curObj.dataCapacity()
        var hasFileDescriptors = curObj.hasFileDescriptors()

        console.log(fullPref
          + " STRING_CREATOR=" + stringCreatorStr
          + ", dataSize=" + dataSize
          + ", dataPosition=" + dataPosition
          + ", dataAvail=" + dataAvail
          + ", dataCapacity=" + dataCapacity
          + ", hasFileDescriptors=" + hasFileDescriptors
        )
      },
      prefixStr,
      FridaAndroidUtil.clsName_Parcel
    )
  }

  /*-------------------- Others --------------------*/

  // Convert com.android.okhttp.Headers$Builder to string
  static HeadersBuilderToString(headersBuilderObj) {
    var headersStr = ""
    if (headersBuilderObj) {
      var headers = headersBuilderObj.build()
      // console.log("headers=" + headers)
      // com.squareup.okhttp.Headers
      headersStr = headers.toString()
    }
    // console.log("headersStr=" + headersStr)
    return headersStr
  }

  /*-------------------- Byte Array --------------------*/

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

  // java ArrayList (byte array / List<Integer> / ArrayList<Map.Entry<String, String>> ) to string
  static listToStr(javaArraryList){
    // var jsArrayList = FridaAndroidUtil.javaByteArrToJsByteArr(javaArraryList)
    // console.log("jsArrayList=" + jsArrayList)
    // var jsArrayListStr = jsArrayList.toString()
    // console.log("jsArrayListStr=" + jsArrayListStr)
    // return jsArrayListStr
    var javaObjList = javaArraryList.toArray()
    console.log("javaObjList=" +  javaObjList)
    var javaObjListStr = javaObjList.toString()
    console.log("javaObjListStr=" +  javaObjListStr)
    return javaObjListStr
  }

  /*-------------------- ByteBuffer --------------------*/

  // java ByteBuffer to String
  static javaByteBufferToStr(byteBufer, isFlip=true){
    // console.log(`javaByteBufferToStr: byteBufer=${byteBufer}`)
    // javaByteBufferToStr: byteBufer=java.nio.DirectByteBuffer[pos=793 lim=16375 cap=16375]
    if(isFlip){
      byteBufer.flip() // rewind to start position
      console.log(`after flip: ${byteBufer}`)
      // after java.nio.DirectByteBuffer[pos=0 lim=793 cap=16375] flip
    }
    // var utf8CharBuffer = FridaAndroidUtil.StandardCharsets.UTF_8.decode(byteBufer)
    // var charsetUtf8 = FridaAndroidUtil.StandardCharsets.UTF_8
    var charsetUtf8 = FridaAndroidUtil.StandardCharsets.UTF_8.value
    // console.log("charsetUtf8=" + charsetUtf8)
    // charsetUtf8=UTF-8
    var utf8CharBuffer = charsetUtf8.decode(byteBufer)
    // console.log("utf8CharBuffer=" + utf8CharBuffer)
    var utf8BufStr = utf8CharBuffer.toString()
    // console.log("utf8BufStr=" + utf8BufStr)
    return utf8BufStr
  }


  /*-------------------- Map --------------------*/

  // check whether the key in keyList exists in keys of map
  static existKeysInMap(curMap, keyList){
    var foundKey = false

    var keys = curMap.keySet()
    var keyIterator = keys.iterator()
    while (keyIterator.hasNext()) {
      var curKey = keyIterator.next()
      // console.log("curKey=" + curKey)
      var curKeyStr = curKey.toString()
      // console.log("curKeyStr=" + curKeyStr)
      foundKey = keyList.includes(curKeyStr)
      if(foundKey) {
        break
      }
    }

    // if(foundKey) {
    //   console.log(`existKeysInMap: curMap=${FridaAndroidUtil.mapToStr(curMap)}, keyList=${keyList} => foundKey=${foundKey}`)
    // }
    return foundKey
  }

  // convert Java map/Collections (java.util.HashMap / java.util.Collections$UnmodifiableMap) to key=value string list
  static mapToKeyValueStrList(curMap){
    var keyValStrList = []
    if((null != curMap) && (curMap != undefined)) {
      var keys = curMap.keySet()
      // console.log("keys=" + keys)
      var keyIterator = keys.iterator()
      // console.log("keyIterator=" + keyIterator)
      while (keyIterator.hasNext()) {
        var curKey = keyIterator.next()
        // console.log("curKey=" + curKey)
        var curValue = curMap.get(curKey)
        // console.log("curValue=" + curValue)
        var keyValStr = `${curKey}=${curValue}`
        // console.log("keyValStr=" + keyValStr)
        keyValStrList.push(keyValStr)
      }
    }
    // console.log("keyValStrList=" + keyValStrList)
    return keyValStrList
  }

  // convert Java map/Collections (java.util.HashMap / java.util.Collections$UnmodifiableMap) to string
  static mapToStr(curMap){
    //  curMap="<instance: java.util.Map, $className: java.util.HashMap>"
    // return JSON.stringify(curMap, (key, value) => (value instanceof Map ? [...value] : value));
    // var keyValStrList = this.mapToKeyValueStrList(curMap)
    var keyValStrList = FridaAndroidUtil.mapToKeyValueStrList(curMap)
    // console.log("keyValStrList=" + keyValStrList)
    var mapStr = keyValStrList.join(", ")
    var mapStr = `[${mapStr}]`
    // console.log("mapStr=" + mapStr)
    return mapStr
  }

  /*-------------------- Set --------------------*/

  // convert Java Set to js string
  static setToStr(curSet){
    // console.log(`setToStr: curSet: type=${typeof curSet}, val=${curSet}`)
    var setStr = ""
    if((null != curSet) && (curSet != undefined)) {
      var setIter = curSet.iterator()
      var itemArr = []
      while (setIter.hasNext()) {
        var curItem = setIter.next();
        // 如果 item 是 Java 对象，优先 toString()
        try {
          itemArr.push(curItem.toString())
        } catch (e) {
          itemArr.push(item)
        }
      }
      setStr = JSON.stringify(itemArr, null, 2)
    } else {
      setStr = "null"
    }
    // console.log(`curSet=${curSet} => setStr=${setStr}`)
    return setStr
  }

  /*-------------------- Class --------------------*/

  // get java class name from clazz
  // example:
  //  clazz=0x35 -> className=java.lang.ref.Reference
  //  clazz=0xa1 -> className=com.tencent.wcdb.database.SQLiteConnection
  //  clazz=0x91 -> className=java.lang.String
  //  clazz=0x42a6 -> jclassName=java.lang.Integer
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

    // var logPrefix = ""
    // if (isFoundCache){
    //   logPrefix = "Cached: "
    // }
    // console.log(logPrefix + "clazz=" + clazz + "-> className=" + className)
    return className
  }

  // get java class name from object
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

  // generate the class name string
  // eg: "<clsName=fjiq>"
  static genClassNameStr(curObj){
    var objClsName = FridaAndroidUtil.getJavaClassName(curObj)
    var classNameStr = `<clsName=${objClsName}>`
    return classNameStr
  }

  // generate the class name and value string from current object
  // eg: "<clsName=fjiq>=[object Object]"
  static valueToNameStr(curObj){
    var retStr = ""
    if (curObj){
      var classNameStr = FridaAndroidUtil.genClassNameStr(curObj)
      retStr = `${classNameStr}=${curObj}`
    } else {
      retStr = "<clsName=null>=null"
    }
    return retStr
  }

  static isJavaClass(curObj, expectedClassName){
    var clsName = FridaAndroidUtil.getJavaClassName(curObj)
    // console.log("clsName=" + clsName)
    var isCls = clsName === expectedClassName
    // console.log("isCls=" + isCls)
    return isCls
  } 

  // cast current object to destination class instance
  static castToJavaClass(curObj, toClassName){
    if(curObj){
      // // for debug
      // var objClsName  =FridaAndroidUtil.getJavaClassName(curObj)
      // console.log("objClsName=" + objClsName)

      const toClass = Java.use(toClassName)
      // console.log("toClass=" + toClass)
      var toClassObj = Java.cast(curObj, toClass)
      // console.log("toClassObj=" + toClassObj)
      return toClassObj
    } else{
      return null
    }
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
    console.log("---use getDeclaredMethods---")

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
    console.log("---use getDeclaredFields---")

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


  /*-------------------- Stack & Function Call & Log --------------------*/

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
    var stackStr = prefix + "java Stack:" + linePrefix + stackElements[0] //method//stackElements[0].getMethodName()
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

  static printNothing(funcName, funcParaDict){
  }

  static printFunctionCallStr(funcName, funcParaDict){
    // var functionCallStr = this.genFunctionCallStr(funcName, funcParaDict)
    var functionCallStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)
    console.log(functionCallStr)
  }

  // generate function call and stack string
  static genFunctionCallAndStack(funcName, funcParaDict, isPrintDelimiter=true){
    // console.log(`funcName=${funcName}, funcParaDict=${funcParaDict}, isPrintDelimiter=${isPrintDelimiter}`)
    var functionCallAndStackStr = ""

    var functionCallStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)

    var stackStr = FridaAndroidUtil.genStackStr(funcName)

    var delimiterStr = ""
    if(isPrintDelimiter){
      var delimiterFuncName = funcName
      const LineMaxSize = 80
      // const LineMaxSize = 120
      // const LineMaxSize = 160
      if (funcName.length > LineMaxSize) {
        // ConnectionsManager.init(version,layer,apiId,deviceModel,systemVersion,appVersion,langCode,systemLangCode,configPath,logPath,regId,cFingerprint,timezoneOffset,userId,userPremium,enablePushConnection) -> ConnectionsManager.init
        // var shortFuncName = funcName.replace('/([\w\.\:]+)\(.+\)/', "$1")
        var shortFuncName = funcName.replace(/([\w\.\:]+)\(.+\)/, "$1")
        // console.log("shortFuncName=" + shortFuncName)
        delimiterFuncName = shortFuncName
      }
      // JsUtil.logStr(delimiterFuncName)
      delimiterStr = JsUtil.generateLineStr(delimiterFuncName, true, "=", LineMaxSize)
      delimiterStr = delimiterStr + "\n"
      // console.log("delimiterStr=" + delimiterStr)
    }

    var functionCallAndStackStr = `${delimiterStr}${functionCallStr}\n${stackStr}`
    return functionCallAndStackStr
  }

  // Check whether to show log or not, and show (function call and stack) log if necessary
  static showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict, isShowLogDefault=true, genLogFunc=FridaAndroidUtil.genFunctionCallAndStack){
    var isShowLog = isShowLogDefault
    var curLogStr = genLogFunc(funcName, funcParaDict)

    if (null != callback_isShowLog) {
      isShowLog = callback_isShowLog(curLogStr)
    }

    if (isShowLog){
      console.log(curLogStr)
    }

    return isShowLog
  }

  // Check whether to show log or not, and show input log if necessary
  static showLogIfNecessary(callback_isShowLog, curLogStr, isShowLogDefault=true){
    var isShowLog = isShowLogDefault

    if (null != callback_isShowLog) {
      isShowLog = callback_isShowLog(curLogStr)
    }

    if (isShowLog){
      console.log(curLogStr)
    }

    return isShowLog
  }

  // print Function call and stack trace string
  static printFunctionCallAndStack(funcName, funcParaDict, whiteList=undefined, isPrintDelimiter=true){
    // console.log("whiteList=" + whiteList + ", isPrintDelimiter=" + isPrintDelimiter)

    var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict, isPrintDelimiter)

    var needPrint = true

    if (whiteList != undefined) {
      needPrint = false

      for (const curFilter of whiteList) {
        // console.log("curFilter=" + curFilter)
        if (funcCallAndStackStr.includes(curFilter)) {
          needPrint = true
          // console.log("needPrint=" + needPrint)
          break
        }
      }
    }

    if (needPrint) {
      console.log(funcCallAndStackStr)
    }
  }

  // common function to decide whether to show log or not
  static func_isShowLog_common(curStr, includeList=[], excludeList=[]){
    // let isShowLog = true
    let isShowLog = false

    // const includeList = [
    //   "X.02J",
    // ]
    for(const eachInclude of includeList){
      if (curStr.includes(eachInclude)){
        isShowLog = true
        break
      }
    }

    // const excludeList = [
    // ]
    // console.log(`excludeList=${excludeList}`)
    for(const eachExclude of excludeList){
      // console.log(`eachExclude=${eachExclude}`)
      if (curStr.includes(eachExclude)){
        // console.log(`eachExclude=${eachExclude} inside curStr=${curStr} => should exclude => is not show log`)
        isShowLog = false
        break
      }
    }

    return isShowLog
  }

  /*-------------------- Class Loder --------------------*/

  static findOverloadFunction(overloads, argTypeList, retType=null){
    var foundOverloadFunc = null

    var argTypeNum = argTypeList.length
    // console.log("argTypeNum=" + argTypeNum)

    overloads.find( function(curOverloadFunc) {
      var overloadArgTypeList = curOverloadFunc.argumentTypes
      // console.log("overloadArgTypeList=" + overloadArgTypeList)
      if ((overloadArgTypeList) && (argTypeNum == overloadArgTypeList.length)){
        var argsFromOverload = curOverloadFunc.argumentTypes.map(argType => argType.className)
        // console.log("argsFromOverload=" + argsFromOverload)
        var overloadArgListJsonStr = JSON.stringify(argsFromOverload)
        // console.log("overloadArgListJsonStr=" + overloadArgListJsonStr)
        var inputArgListJsonStr = JSON.stringify(argTypeList)
        // console.log("inputArgListJsonStr=" + inputArgListJsonStr)
        var isArgsSame = overloadArgListJsonStr === inputArgListJsonStr
        // console.log("isArgsSame=" + isArgsSame)
        if (isArgsSame){
          if (retType){
            var mappedTypeStr = retType
            if (mappedTypeStr in FridaAndroidUtil.FridaDexTypeMapppingDict){
              mappedTypeStr = FridaAndroidUtil.FridaDexTypeMapppingDict[mappedTypeStr]
              // console.log("mapped mappedTypeStr=" + mappedTypeStr)
            }

            var overloadFuncRetType = curOverloadFunc.returnType
            // console.log("overloadFuncRetType=" + overloadFuncRetType)
            var overloadFuncRetTypeStr = overloadFuncRetType.toString()
            // console.log("overloadFuncRetTypeStr=" + overloadFuncRetTypeStr)
            if (mappedTypeStr === overloadFuncRetTypeStr){
              foundOverloadFunc = curOverloadFunc
              return foundOverloadFunc
            } else {
              // console.log("returnType not same: mapped=" + mappedTypeStr + " != current=" + overloadFuncRetTypeStr)
            }
          }
        }
      }
    })

    // console.log("foundOverloadFunc=" + foundOverloadFunc)
    return foundOverloadFunc
  }

  static findClassLoader(className){
    var foundClassLoader = null

    const classLoaders = Java.enumerateClassLoadersSync()
    // console.log("classLoaders=" + classLoaders + ", type=" + (typeof classLoaders))

    for (const loaderIdx in classLoaders) {
      var curClassLoader = classLoaders[loaderIdx]
      var loaderClsName = FridaAndroidUtil.getJavaClassName(curClassLoader)
      console.log(`[${loaderIdx}] loaderClsName=${loaderClsName}, curClassLoader=${curClassLoader}`)

      try {
        if (curClassLoader.findClass(className)){
          // console.log(`Found ${className} in loader ${curClassLoader}`)
          // Found org.chromium.net.impl.CronetUrlRequest in loader dalvik.system.DelegateLastClassLoader[DexPathList[[zip file "/data/user_de/0/com.google.android.gms/app_chimera/m/00000013/CronetDynamite.apk"],nativeLibraryDirectories=[/data/user_de/0/com.google.android.gms/app_chimera/m/00000013/CronetDynamite.apk!/lib/arm64-v8a, /system/lib64, /system_ext/lib64]]]
          foundClassLoader = curClassLoader
          break
        }
      } catch (err){
        // console.log(`${err}`)
      }
    }

    console.log(`findClassLoader: className=${className} => foundClassLoader=${foundClassLoader}`)
    return foundClassLoader
  }

  static setClassLoder(newClassLoader){
    // var oldClassLoader = Java.classFactory.loader
    // console.log(`oldClassLoader=${oldClassLoader}`)
    Java.classFactory.loader = newClassLoader
    console.log(`Set ClassLoader to ${newClassLoader}`)
  }

  static updateClassLoader(className){
    var foundClassLoader = FridaAndroidUtil.findClassLoader(className)
    console.log(`foundClassLoader=${foundClassLoader}`)
    if(foundClassLoader) {
      FridaAndroidUtil.setClassLoder(foundClassLoader)
    } else {
      console.error(`Fail to find classLoader for ${className}`)
    }
  }

}

// https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaHookAndroidJava.js
// Updated: 20251205
// Frida hook common Android/Java class
class FridaHookAndroidJava {
  constructor() {
    console.log("FridaHookAndroidJava constructor")
  }

  static JSONObject(callback_isShowLog=null) {
    var className_JSONObject = "org.json.JSONObject"
    // FridaAndroidUtil.printClassAllMethodsFields(className_JSONObject)

    var cls_JSONObject = Java.use(className_JSONObject)
    console.log("cls_JSONObject=" + cls_JSONObject)

    // curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    var curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // JSONObject	putOpt(String name, Object value)
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
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retJsonObj = this.put(str, obj)
        if (isShowLog){
          console.log(funcName + " => retJsonObj=" + retJsonObj)
        }
        return retJsonObj
      }
    }

    // String	toString()
    // public String toString()
    var func_JSONObject_toString_0p = cls_JSONObject.toString.overload()
    console.log("func_JSONObject_toString_0p=" + func_JSONObject_toString_0p)
    if (func_JSONObject_toString_0p) {
      func_JSONObject_toString_0p.implementation = function () {
        var funcName = "JSONObject.toString()"
        var funcParaDict = {
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retJsonStr = this.toString()
        if (isShowLog){
          console.log(funcName + " => retJsonStr=" + retJsonStr)
        }
        return retJsonStr
      }
    }

  }

  static HashMap(callback_isShowLog=null) {
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
        var funcName = "HashMap.put"
        var funcParaDict = {
          "keyObj": keyObj,
          "valueObj": valueObj,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retObj = this.put(keyObj, valueObj)

        if (isShowLog) {
          console.log(funcName + " => retObj=" + retObj)
        }

        return retObj
      }
    }

    // public void java.util.HashMap.putAll(java.util.Map)
    // var func_HashMap_putAll = cls_HashMap.putAll('java.util.Map')
    var func_HashMap_putAll = cls_HashMap.putAll
    console.log("func_HashMap_putAll=" + func_HashMap_putAll)
    if (func_HashMap_putAll) {
      func_HashMap_putAll.implementation = function (newMap) {
        var funcName = "HashMap.putAll"
        var funcParaDict = {
          "newMap": newMap,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        this.putAll(newMap)
        return
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
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retValObj = this.get(keyObj)

        if (isShowLog) {
          console.log(funcName + " => retValObj=" + retValObj)
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
        this.$init()
        var newBuilder_void = this
        console.log("newBuilder_void=" + newBuilder_void)
        return
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
    //     this.$init(request)
    //     var newBuilder_req = this
    //     console.log("newBuilder_req=" + newBuilder_req)
    //     return
    //   }
    // }

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

    const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    // const curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // Note: Xiaomi8 not exist: getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager$ApplicationInfoFlags')
    // public ApplicationInfo getApplicationInfo(String packageName, PackageManager.ApplicationInfoFlags flags)
    // public android.content.pm.ApplicationInfo android.content.pm.PackageManager.getApplicationInfo(java.lang.String,android.content.pm.PackageManager$ApplicationInfoFlags) throws android.content.pm.PackageManager$NameNotFoundException
    // var func_PackageManager_getApplicationInfo = cls_PackageManager.getApplicationInfo
    var func_PackageManager_getApplicationInfo = cls_PackageManager.getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager$ApplicationInfoFlags')
    // var func_PackageManager_getApplicationInfo = cls_PackageManager.getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager.ApplicationInfoFlags')
    console.log("func_PackageManager_getApplicationInfo=" + func_PackageManager_getApplicationInfo)
    if (func_PackageManager_getApplicationInfo) {
      func_PackageManager_getApplicationInfo.implementation = function (packageName, flags) {
        var funcName = "PackageManager.getApplicationInfo(packageName,flags)"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }

        var retAppInfo = this.getApplicationInfo(packageName, flags)

        var isMatch = false
        if (null != PackageManager_getApplicationInfo){
          isMatch = PackageManager_getApplicationInfo(packageName)
        }

        if (isMatch){
          curLogFunc(funcName, funcParaDict)

          // do hook bypass
          retAppInfo = ApplicationInfo()
        } else {
          // no hook
        }

        console.log("retAppInfo=" + retAppInfo)
        return retAppInfo
      }
    }

    // public abstract ApplicationInfo getApplicationInfo(String packageName, int flags)
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
          curLogFunc(funcName, funcParaDict)

          // // do hook bypass
          // retAppInfo_abstract = ApplicationInfo()
        } else {
          // no hook
        }

        console.log("retAppInfo_abstract=" + retAppInfo_abstract)
        return retAppInfo_abstract
      }
    }


    // abstract PackageInfo getPackageInfo(String packageName, int flags)
    // public abstract android.content.pm.PackageInfo android.content.pm.PackageManager.getPackageInfo(java.lang.String,int) throws android.content.pm.PackageManager$NameNotFoundException
    var func_PackageManager_getPackageInfo_2psi = cls_PackageManager.getPackageInfo.overload('java.lang.String', 'int')
    console.log("func_PackageManager_getPackageInfo_2psi=" + func_PackageManager_getPackageInfo_2psi)
    if (func_PackageManager_getPackageInfo_2psi) {
      func_PackageManager_getPackageInfo_2psi.implementation = function (packageName, flags) {
        var funcName = "PackageManager.getPackageInfo_2psi"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        curLogFunc(funcName, funcParaDict)

        var retPackageInfo_2psi = this.getPackageInfo(packageName, flags)
        console.log(funcName + " => retPackageInfo_2psi=" + retPackageInfo_2psi)
        return retPackageInfo_2psi
      }
    }

    // PackageInfo getPackageInfo(String packageName, PackageManager.PackageInfoFlags flags)
    // public android.content.pm.PackageInfo android.content.pm.PackageManager.getPackageInfo(java.lang.String,android.content.pm.PackageManager$PackageInfoFlags) throws android.content.pm.PackageManager$NameNotFoundException
    var func_PackageManager_getPackageInfo_2ppf = cls_PackageManager.getPackageInfo.overload('java.lang.String', 'android.content.pm.PackageManager$PackageInfoFlags')
    console.log("func_PackageManager_getPackageInfo_2ppf=" + func_PackageManager_getPackageInfo_2ppf)
    if (func_PackageManager_getPackageInfo_2ppf) {
      func_PackageManager_getPackageInfo_2ppf.implementation = function (packageName, flags) {
        var funcName = "PackageManager.getPackageInfo_2ppf"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        curLogFunc(funcName, funcParaDict)

        var retPackageInfo_2ppf = this.getPackageInfo(packageName, flags)
        console.log(funcName + " => retPackageInfo_2ppf=" + retPackageInfo_2ppf)
        var isGetSignatures = PackageManager.GET_SIGNATURES & flags
        console.log(funcName + " isGetSignatures=" + isGetSignatures)
        if(isGetSignatures){
          var signatures = retPackageInfo_2ppf.signatures
          console.log(funcName + " signatures=" + signatures)
        }
        return retPackageInfo_2ppf
      }
    }

    // public abstract int checkPermission(String permName, String packageName)
    // public abstract int android.content.pm.PackageManager.checkPermission(java.lang.String,java.lang.String)
    var func_PackageManager_checkPermission = cls_PackageManager.checkPermission
    console.log("func_PackageManager_checkPermission=" + func_PackageManager_checkPermission)
    if (func_PackageManager_checkPermission) {
      func_PackageManager_checkPermission.implementation = function (permName, packageName) {
        var funcName = "PackageManager.checkPermission"
        var funcParaDict = {
          "permName": permName,
          "packageName": packageName,
        }
        curLogFunc(funcName, funcParaDict)

        var retPermissionInt = this.checkPermission(permName, packageName)
        console.log(funcName + " => retPermissionInt=" + retPermissionInt)
        return retPermissionInt
      }
    }

  }

  static Signature() {
    var className_Signature = "android.content.pm.Signature"
    // FridaAndroidUtil.printClassAllMethodsFields(className_Signature)

    var cls_Signature = Java.use(className_Signature)
    console.log("cls_Signature=" + cls_Signature)

    const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    // const curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // public byte[] toByteArray()
    // public byte[] android.content.pm.Signature.toByteArray()
    var cls_Signature_toByteArray = cls_Signature.toByteArray
    console.log("cls_Signature_toByteArray=" + cls_Signature_toByteArray)
    if (cls_Signature_toByteArray) {
      cls_Signature_toByteArray.implementation = function () {
        var funcName = "Signature.toByteArray"
        var funcParaDict = {
        }
        curLogFunc(funcName, funcParaDict)

        var retBytes = this.toByteArray()
        console.log(funcName + " => retBytes: len=" + retBytes.length + ", var=" + retBytes)
        return retBytes
      }
    }

  }

  static ApplicationPackageManager() {
    var clsName_ApplicationPackageManager = "android.app.ApplicationPackageManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_ApplicationPackageManager)

    var cls_ApplicationPackageManager = Java.use(clsName_ApplicationPackageManager)
    console.log("cls_ApplicationPackageManager=" + cls_ApplicationPackageManager)

    
    // public int checkPermission(String permName, String pkgName)
    // public int android.app.ApplicationPackageManager.checkPermission(java.lang.String,java.lang.String)
    var func_ApplicationPackageManager_checkPermission = cls_ApplicationPackageManager.checkPermission
    console.log("func_ApplicationPackageManager_checkPermission=" + func_ApplicationPackageManager_checkPermission)
    if (func_ApplicationPackageManager_checkPermission) {
      func_ApplicationPackageManager_checkPermission.implementation = function (permName, pkgName) {
        var funcName = "ApplicationPackageManager.checkPermission"
        var funcParaDict = {
          "permName": permName,
          "pkgName": pkgName,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInt = this.checkPermission(permName, pkgName)
        console.log(funcName + " => retInt=" + retInt)
        return retInt
      }
    }

    // public ApplicationInfo getApplicationInfo(String packageName, int flags) throws NameNotFoundException
    // public android.content.pm.ApplicationInfo android.app.ApplicationPackageManager.getApplicationInfo(java.lang.String,int) throws android.content.pm.PackageManager$NameNotFoundException
    var func_ApplicationPackageManager_getApplicationInfo_2ppf = cls_ApplicationPackageManager.getApplicationInfo.overload('java.lang.String', 'int')
    console.log("func_ApplicationPackageManager_getApplicationInfo_2ppf=" + func_ApplicationPackageManager_getApplicationInfo_2ppf)
    if (func_ApplicationPackageManager_getApplicationInfo_2ppf) {
      func_ApplicationPackageManager_getApplicationInfo_2ppf.implementation = function (packageName, flags) {
        var funcName = "ApplicationPackageManager.getApplicationInfo_2ppf"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retApplicationInfo_2ppf = this.getApplicationInfo(packageName, flags)
        console.log(funcName + " => retApplicationInfo_2ppf=" + retApplicationInfo_2ppf)
        return retApplicationInfo_2ppf
      }
    }

    // public ApplicationInfo getApplicationInfo(String packageName, ApplicationInfoFlags flags) throws NameNotFoundException
    // public android.content.pm.ApplicationInfo android.app.ApplicationPackageManager.getApplicationInfo(java.lang.String,android.content.pm.PackageManager$ApplicationInfoFlags) throws android.content.pm.PackageManager$NameNotFoundException
    var func_ApplicationPackageManager_getApplicationInfo_2ppf = cls_ApplicationPackageManager.getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager$ApplicationInfoFlags')
    console.log("func_ApplicationPackageManager_getApplicationInfo_2ppf=" + func_ApplicationPackageManager_getApplicationInfo_2ppf)
    if (func_ApplicationPackageManager_getApplicationInfo_2ppf) {
      func_ApplicationPackageManager_getApplicationInfo_2ppf.implementation = function (packageName, flags) {
        var funcName = "ApplicationPackageManager.getApplicationInfo_2ppf"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retApplicationInfo_2ppf = this.getApplicationInfo(packageName, flags)
        console.log(funcName + " => retApplicationInfo_2ppf=" + retApplicationInfo_2ppf)
        return retApplicationInfo_2ppf
      }
    }

    // public PackageInfo getPackageInfo(String packageName, int flags) throws NameNotFoundException
    // public android.content.pm.PackageInfo android.app.ApplicationPackageManager.getPackageInfo(java.lang.String,int) throws android.content.pm.PackageManager$NameNotFoundException
    var func_ApplicationPackageManager_getPackageInfo_2ppf = cls_ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int')
    console.log("func_ApplicationPackageManager_getPackageInfo_2ppf=" + func_ApplicationPackageManager_getPackageInfo_2ppf)
    if (func_ApplicationPackageManager_getPackageInfo_2ppf) {
      func_ApplicationPackageManager_getPackageInfo_2ppf.implementation = function (packageName, flags) {
        var funcName = "ApplicationPackageManager.getPackageInfo_2ppf"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retPackageInfo_2ppf = this.getPackageInfo(packageName, flags)
        console.log(funcName + " => retPackageInfo_2ppf=" + retPackageInfo_2ppf)
        return retPackageInfo_2ppf
      }
    }

    // public PackageInfo getPackageInfo(String packageName, PackageInfoFlags flags) throws NameNotFoundException
    // public android.content.pm.PackageInfo android.app.ApplicationPackageManager.getPackageInfo(java.lang.String,android.content.pm.PackageManager$PackageInfoFlags) throws android.content.pm.PackageManager$NameNotFoundException
    var func_ApplicationPackageManager_getPackageInfo_2ppf = cls_ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'android.content.pm.PackageManager$PackageInfoFlags')
    console.log("func_ApplicationPackageManager_getPackageInfo_2ppf=" + func_ApplicationPackageManager_getPackageInfo_2ppf)
    if (func_ApplicationPackageManager_getPackageInfo_2ppf) {
      func_ApplicationPackageManager_getPackageInfo_2ppf.implementation = function (packageName, flags) {
        var funcName = "ApplicationPackageManager.getPackageInfo_2ppf"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retPackageInfo_2ppf = this.getPackageInfo(packageName, flags)
        console.log(funcName + " => retPackageInfo_2ppf=" + retPackageInfo_2ppf)
        return retPackageInfo_2ppf
      }
    }

    // public PackageInfo getPackageInfo(VersionedPackage versionedPackage, int flags) throws NameNotFoundException
    // public android.content.pm.PackageInfo android.app.ApplicationPackageManager.getPackageInfo(android.content.pm.VersionedPackage,int) throws android.content.pm.PackageManager$NameNotFoundException
    var func_ApplicationPackageManager_getPackageInfo_2pvf = cls_ApplicationPackageManager.getPackageInfo.overload('android.content.pm.VersionedPackage', 'int')
    console.log("func_ApplicationPackageManager_getPackageInfo_2pvf=" + func_ApplicationPackageManager_getPackageInfo_2pvf)
    if (func_ApplicationPackageManager_getPackageInfo_2pvf) {
      func_ApplicationPackageManager_getPackageInfo_2pvf.implementation = function (versionedPackage, flags) {
        var funcName = "ApplicationPackageManager.getPackageInfo_2pvf"
        var funcParaDict = {
          "versionedPackage": versionedPackage,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retPackageInfo_2pvf = this.getPackageInfo(versionedPackage, flags)
        console.log(funcName + " => retPackageInfo_2pvf=" + retPackageInfo_2pvf)
        return retPackageInfo_2pvf
      }
    }

    // public PackageInfo getPackageInfo(VersionedPackage versionedPackage, PackageInfoFlags flags) throws NameNotFoundException
    // public android.content.pm.PackageInfo android.app.ApplicationPackageManager.getPackageInfo(android.content.pm.VersionedPackage,android.content.pm.PackageManager$PackageInfoFlags) throws android.content.pm.PackageManager$NameNotFoundException
    var func_ApplicationPackageManager_getPackageInfo_2pvf = cls_ApplicationPackageManager.getPackageInfo.overload('android.content.pm.VersionedPackage', 'android.content.pm.PackageManager$PackageInfoFlags')
    console.log("func_ApplicationPackageManager_getPackageInfo_2pvf=" + func_ApplicationPackageManager_getPackageInfo_2pvf)
    if (func_ApplicationPackageManager_getPackageInfo_2pvf) {
      func_ApplicationPackageManager_getPackageInfo_2pvf.implementation = function (versionedPackage, flags) {
        var funcName = "ApplicationPackageManager.getPackageInfo_2pvf"
        var funcParaDict = {
          "versionedPackage": versionedPackage,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retPackageInfo_2pvf = this.getPackageInfo(versionedPackage, flags)
        console.log(funcName + " => retPackageInfo_2pvf=" + retPackageInfo_2pvf)
        return retPackageInfo_2pvf
      }
    }

    // public abstract boolean hasSystemFeature(String featureName)
    // public abstract boolean android.content.pm.PackageManager.hasSystemFeature(java.lang.String)
    var func_ApplicationPackageManager_hasSystemFeature_1pf = cls_ApplicationPackageManager.hasSystemFeature.overload('java.lang.String')
    console.log("func_ApplicationPackageManager_hasSystemFeature_1pf=" + func_ApplicationPackageManager_hasSystemFeature_1pf)
    if (func_ApplicationPackageManager_hasSystemFeature_1pf) {
      func_ApplicationPackageManager_hasSystemFeature_1pf.implementation = function (featureName) {
        var funcName = "ApplicationPackageManager.hasSystemFeature(featureName)"
        var funcParaDict = {
          "featureName": featureName,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retHasSystemFeature_1pf = this.hasSystemFeature(featureName)
        console.log(funcName + " => retHasSystemFeature_1pf=" + retHasSystemFeature_1pf)
        return retHasSystemFeature_1pf
      }
    }

    // public abstract boolean hasSystemFeature(String featureName, int version)
    // public abstract boolean android.content.pm.PackageManager.hasSystemFeature(java.lang.String,int)
    var func_ApplicationPackageManager_hasSystemFeature_2pfv = cls_ApplicationPackageManager.hasSystemFeature.overload('java.lang.String', 'int')
    console.log("func_ApplicationPackageManager_hasSystemFeature_2pfv=" + func_ApplicationPackageManager_hasSystemFeature_2pfv)
    if (func_ApplicationPackageManager_hasSystemFeature_2pfv) {
      func_ApplicationPackageManager_hasSystemFeature_2pfv.implementation = function (featureName, version) {
        var funcName = "ApplicationPackageManager.hasSystemFeature(featureName,version)"
        var funcParaDict = {
          "featureName": featureName,
          "version": version,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retHasSystemFeature_2pfv = this.hasSystemFeature(featureName, version)
        console.log(funcName + " => retHasSystemFeature_2pfv=" + retHasSystemFeature_2pfv)
        return retHasSystemFeature_2pfv
      }
    }

    // public String[] getSystemSharedLibraryNames() {
    // public java.lang.String[] android.app.ApplicationPackageManager.getSystemSharedLibraryNames()
    var func_ApplicationPackageManager_getSystemSharedLibraryNames = cls_ApplicationPackageManager.getSystemSharedLibraryNames
    console.log("func_ApplicationPackageManager_getSystemSharedLibraryNames=" + func_ApplicationPackageManager_getSystemSharedLibraryNames)
    if (func_ApplicationPackageManager_getSystemSharedLibraryNames) {
      func_ApplicationPackageManager_getSystemSharedLibraryNames.implementation = function () {
        var funcName = "ApplicationPackageManager.getSystemSharedLibraryNames"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var systemSharedLibraryNames = this.getSystemSharedLibraryNames()
        console.log(funcName + " => systemSharedLibraryNames=" + systemSharedLibraryNames)
        return systemSharedLibraryNames
      }
    }

    // public FeatureInfo[] getSystemAvailableFeatures() {
    // public android.content.pm.FeatureInfo[] android.app.ApplicationPackageManager.getSystemAvailableFeatures()
    var func_ApplicationPackageManager_getSystemAvailableFeatures = cls_ApplicationPackageManager.getSystemAvailableFeatures
    console.log("func_ApplicationPackageManager_getSystemAvailableFeatures=" + func_ApplicationPackageManager_getSystemAvailableFeatures)
    if (func_ApplicationPackageManager_getSystemAvailableFeatures) {
      func_ApplicationPackageManager_getSystemAvailableFeatures.implementation = function () {
        var funcName = "ApplicationPackageManager.getSystemAvailableFeatures"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var systemAvailableFeatures = this.getSystemAvailableFeatures()
        console.log(funcName + " => systemAvailableFeatures=" + systemAvailableFeatures)
        return systemAvailableFeatures
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


  static urlCommon_filterLogByUrl(curUrl, funcName, funcParaDict, curLogFunc, callback_isShowLog=null) {
    var urlLog = `${funcName}: curUrl=${curUrl}`
    // console.log(urlLog)
    var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, urlLog)
    if(isShowLog) {
      curLogFunc(funcName, funcParaDict)
    }

    return isShowLog
  }

  static HttpURLConnectionImpl(callback_isShowLog=null) {
    var clsName_HttpURLConnectionImpl = "com.android.okhttp.internal.huc.HttpURLConnectionImpl"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_HttpURLConnectionImpl)

    var cls_HttpURLConnectionImpl = Java.use(clsName_HttpURLConnectionImpl)
    console.log("cls_HttpURLConnectionImpl=" + cls_HttpURLConnectionImpl)

    const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    // const curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // public HttpURLConnectionImpl(URL url, OkHttpClient client) {
    // 
    var func_HttpURLConnectionImpl_HttpURLConnectionImpl_2p = cls_HttpURLConnectionImpl.$init.overload("java.net.URL", "com.android.okhttp.OkHttpClient")
    console.log("func_HttpURLConnectionImpl_HttpURLConnectionImpl_2p=" + func_HttpURLConnectionImpl_HttpURLConnectionImpl_2p)
    if (func_HttpURLConnectionImpl_HttpURLConnectionImpl_2p) {
      func_HttpURLConnectionImpl_HttpURLConnectionImpl_2p.implementation = function (url, client) {
        var funcName = "HttpURLConnectionImpl(url,client)"
        var funcParaDict = {
          "url": url,
          "client": client,
        }
        var funcCallStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, funcCallStr)
        if(isShowLog) {
          curLogFunc(funcName, funcParaDict)
        }

        this.$init(url, client)
        if(isShowLog) {
          var newHttpURLConnectionImpl_2p = this
          console.log(`${funcName} => newHttpURLConnectionImpl_2p=${newHttpURLConnectionImpl_2p}`)
        }
        return
      }
    }

    // public HttpURLConnectionImpl(URL url, OkHttpClient client, URLFilter urlFilter) {
    // 
    var func_HttpURLConnectionImpl_HttpURLConnectionImpl_3p = cls_HttpURLConnectionImpl.$init.overload("java.net.URL", "com.android.okhttp.OkHttpClient", "com.android.okhttp.internal.URLFilter")
    console.log("func_HttpURLConnectionImpl_HttpURLConnectionImpl_3p=" + func_HttpURLConnectionImpl_HttpURLConnectionImpl_3p)
    if (func_HttpURLConnectionImpl_HttpURLConnectionImpl_3p) {
      func_HttpURLConnectionImpl_HttpURLConnectionImpl_3p.implementation = function (url, client, urlFilter) {
        var funcName = "HttpURLConnectionImpl(url,client,urlFilter)"
        var funcParaDict = {
          "url": url,
          "client": client,
          "urlFilter": urlFilter,
        }
        var funcCallStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, funcCallStr)
        if(isShowLog) {
          curLogFunc(funcName, funcParaDict)
        }

        this.$init(url, client, urlFilter)
        if(isShowLog) {
          var newHttpURLConnectionImpl_3p = this
          console.log(`${funcName} => newHttpURLConnectionImpl_3p=${newHttpURLConnectionImpl_3p}`)
        }
        return
      }
    }

    // @Override public final void connect() throws IOException {
    // public final void com.android.okhttp.internal.huc.HttpURLConnectionImpl.connect() throws java.io.IOException
    var func_HttpURLConnectionImpl_connect = cls_HttpURLConnectionImpl.connect
    console.log("func_HttpURLConnectionImpl_connect=" + func_HttpURLConnectionImpl_connect)
    if (func_HttpURLConnectionImpl_connect) {
      func_HttpURLConnectionImpl_connect.implementation = function () {
        var funcName = "HttpURLConnectionImpl.connect"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.connect()
        return
      }
    }

    // @Override public final void disconnect() {
    // public final void com.android.okhttp.internal.huc.HttpURLConnectionImpl.disconnect()
    var func_HttpURLConnectionImpl_disconnect = cls_HttpURLConnectionImpl.disconnect
    console.log("func_HttpURLConnectionImpl_disconnect=" + func_HttpURLConnectionImpl_disconnect)
    if (func_HttpURLConnectionImpl_disconnect) {
      func_HttpURLConnectionImpl_disconnect.implementation = function () {
        var funcName = "HttpURLConnectionImpl.disconnect"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.disconnect()
        return
      }
    }

    // @Override public final InputStream getErrorStream() {
    // public final java.io.InputStream com.android.okhttp.internal.huc.HttpURLConnectionImpl.getErrorStream()
    var func_HttpURLConnectionImpl_getErrorStream = cls_HttpURLConnectionImpl.getErrorStream
    console.log("func_HttpURLConnectionImpl_getErrorStream=" + func_HttpURLConnectionImpl_getErrorStream)
    if (func_HttpURLConnectionImpl_getErrorStream) {
      func_HttpURLConnectionImpl_getErrorStream.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getErrorStream"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retErrorStream = this.getErrorStream()
        if (isShowLog) {
          console.log(`${funcName} => retErrorStream=${retErrorStream}`)
        }
        return retErrorStream
      }
    }

    // private Headers getHeaders() throws IOException {
    // private com.android.okhttp.Headers com.android.okhttp.internal.huc.HttpURLConnectionImpl.getHeaders() throws java.io.IOException
    var func_HttpURLConnectionImpl_getHeaders = cls_HttpURLConnectionImpl.getHeaders
    console.log("func_HttpURLConnectionImpl_getHeaders=" + func_HttpURLConnectionImpl_getHeaders)
    if (func_HttpURLConnectionImpl_getHeaders) {
      func_HttpURLConnectionImpl_getHeaders.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getHeaders"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaders = this.getHeaders()
        if (isShowLog) {
          console.log(`${funcName} => retHeaders=${retHeaders}`)
        }
        return retHeaders
      }
    }

    // private static String responseSourceHeader(Response response) {
    // private static java.lang.String com.android.okhttp.internal.huc.HttpURLConnectionImpl.responseSourceHeader(com.android.okhttp.Response)
    var func_HttpURLConnectionImpl_responseSourceHeader = cls_HttpURLConnectionImpl.responseSourceHeader
    console.log("func_HttpURLConnectionImpl_responseSourceHeader=" + func_HttpURLConnectionImpl_responseSourceHeader)
    if (func_HttpURLConnectionImpl_responseSourceHeader) {
      func_HttpURLConnectionImpl_responseSourceHeader.implementation = function (response) {
        var funcName = "HttpURLConnectionImpl.responseSourceHeader"
        var funcParaDict = {
          "response": response,
        }
        // var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        // curLogFunc(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)
        var retString = this.responseSourceHeader(response)
        // if (isShowLog) {
          console.log(`${funcName} => retString=${retString}`)
        // }
        return retString
      }
    }

    // @Override public final String getHeaderField(int position) {
    // public final java.lang.String com.android.okhttp.internal.huc.HttpURLConnectionImpl.getHeaderField(int)
    var func_HttpURLConnectionImpl_getHeaderField_i = cls_HttpURLConnectionImpl.getHeaderField.overload("int")
    console.log("func_HttpURLConnectionImpl_getHeaderField_i=" + func_HttpURLConnectionImpl_getHeaderField_i)
    if (func_HttpURLConnectionImpl_getHeaderField_i) {
      func_HttpURLConnectionImpl_getHeaderField_i.implementation = function (position) {
        var funcName = "HttpURLConnectionImpl.getHeaderField(position)"
        var funcParaDict = {
          "position": position,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaderField_i = this.getHeaderField(position)
        if (isShowLog) {
          console.log(`${funcName} => retHeaderField_i=${retHeaderField_i}`)
        }
        return retHeaderField_i
      }
    }

    // @Override public final String getHeaderField(String fieldName) {
    // public final java.lang.String com.android.okhttp.internal.huc.HttpURLConnectionImpl.getHeaderField(java.lang.String)
    var func_HttpURLConnectionImpl_getHeaderField_str = cls_HttpURLConnectionImpl.getHeaderField.overload("java.lang.String")
    console.log("func_HttpURLConnectionImpl_getHeaderField_str=" + func_HttpURLConnectionImpl_getHeaderField_str)
    if (func_HttpURLConnectionImpl_getHeaderField_str) {
      func_HttpURLConnectionImpl_getHeaderField_str.implementation = function (fieldName) {
        var funcName = "HttpURLConnectionImpl.getHeaderField(fieldName)"
        var funcParaDict = {
          "fieldName": fieldName,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaderField_str = this.getHeaderField(fieldName)
        if (isShowLog) {
          console.log(`${funcName} => retHeaderField_str=${retHeaderField_str}`)
        }
        return retHeaderField_str
      }
    }

    // @Override public final String getHeaderFieldKey(int position) {
    // public final java.lang.String com.android.okhttp.internal.huc.HttpURLConnectionImpl.getHeaderFieldKey(int)
    var func_HttpURLConnectionImpl_getHeaderFieldKey = cls_HttpURLConnectionImpl.getHeaderFieldKey
    console.log("func_HttpURLConnectionImpl_getHeaderFieldKey=" + func_HttpURLConnectionImpl_getHeaderFieldKey)
    if (func_HttpURLConnectionImpl_getHeaderFieldKey) {
      func_HttpURLConnectionImpl_getHeaderFieldKey.implementation = function (position) {
        var funcName = "HttpURLConnectionImpl.getHeaderFieldKey"
        var funcParaDict = {
          "position": position,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaderFieldKey = this.getHeaderFieldKey(position)
        if (isShowLog) {
          console.log(`${funcName} => retHeaderFieldKey=${retHeaderFieldKey}`)
        }
        return retHeaderFieldKey
      }
    }

    // @Override public final Map<String, List<String>> getHeaderFields() {
    // public final java.util.Map com.android.okhttp.internal.huc.HttpURLConnectionImpl.getHeaderFields()
    var func_HttpURLConnectionImpl_getHeaderFields = cls_HttpURLConnectionImpl.getHeaderFields
    console.log("func_HttpURLConnectionImpl_getHeaderFields=" + func_HttpURLConnectionImpl_getHeaderFields)
    if (func_HttpURLConnectionImpl_getHeaderFields) {
      func_HttpURLConnectionImpl_getHeaderFields.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getHeaderFields"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaderFields = this.getHeaderFields()
        if (isShowLog) {
          console.log(`${funcName} => retHeaderFields=${retHeaderFields}`)
        }
        return retHeaderFields
      }
    }

    // @Override public final Map<String, List<String>> getRequestProperties() {
    // public final java.util.Map com.android.okhttp.internal.huc.HttpURLConnectionImpl.getRequestProperties()
    var func_HttpURLConnectionImpl_getRequestProperties = cls_HttpURLConnectionImpl.getRequestProperties
    console.log("func_HttpURLConnectionImpl_getRequestProperties=" + func_HttpURLConnectionImpl_getRequestProperties)
    if (func_HttpURLConnectionImpl_getRequestProperties) {
      func_HttpURLConnectionImpl_getRequestProperties.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getRequestProperties"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retRequestProperties = this.getRequestProperties()
        if (isShowLog) {
          console.log(`${funcName} => retRequestProperties=${retRequestProperties}`)
        }
        return retRequestProperties
      }
    }

    // @Override public final InputStream getInputStream() throws IOException {
    // public final java.io.InputStream com.android.okhttp.internal.huc.HttpURLConnectionImpl.getInputStream() throws java.io.IOException
    var func_HttpURLConnectionImpl_getInputStream = cls_HttpURLConnectionImpl.getInputStream
    console.log("func_HttpURLConnectionImpl_getInputStream=" + func_HttpURLConnectionImpl_getInputStream)
    if (func_HttpURLConnectionImpl_getInputStream) {
      func_HttpURLConnectionImpl_getInputStream.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getInputStream"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retInputStream = this.getInputStream()
        if (isShowLog) {
          console.log(`${funcName} => retInputStream=${retInputStream}`)
        }
        return retInputStream
      }
    }

    // @Override public final OutputStream getOutputStream() throws IOException {
    // public final java.io.OutputStream com.android.okhttp.internal.huc.HttpURLConnectionImpl.getOutputStream() throws java.io.IOException
    var func_HttpURLConnectionImpl_getOutputStream = cls_HttpURLConnectionImpl.getOutputStream
    console.log("func_HttpURLConnectionImpl_getOutputStream=" + func_HttpURLConnectionImpl_getOutputStream)
    if (func_HttpURLConnectionImpl_getOutputStream) {
      func_HttpURLConnectionImpl_getOutputStream.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getOutputStream"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retOutputStream = this.getOutputStream()
        if (isShowLog) {
          console.log(`${funcName} => retOutputStream=${retOutputStream}`)
        }
        return retOutputStream
      }
    }

    // @Override public final Permission getPermission() throws IOException {
    // public final java.security.Permission com.android.okhttp.internal.huc.HttpURLConnectionImpl.getPermission() throws java.io.IOException
    var func_HttpURLConnectionImpl_getPermission = cls_HttpURLConnectionImpl.getPermission
    console.log("func_HttpURLConnectionImpl_getPermission=" + func_HttpURLConnectionImpl_getPermission)
    if (func_HttpURLConnectionImpl_getPermission) {
      func_HttpURLConnectionImpl_getPermission.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getPermission"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retPermission = this.getPermission()
        if (isShowLog) {
          console.log(`${funcName} => retPermission=${retPermission}`)
        }
        return retPermission
      }
    }

    // @Override public final String getRequestProperty(String field) {
    // public final java.lang.String com.android.okhttp.internal.huc.HttpURLConnectionImpl.getRequestProperty(java.lang.String)
    var func_HttpURLConnectionImpl_getRequestProperty = cls_HttpURLConnectionImpl.getRequestProperty
    console.log("func_HttpURLConnectionImpl_getRequestProperty=" + func_HttpURLConnectionImpl_getRequestProperty)
    if (func_HttpURLConnectionImpl_getRequestProperty) {
      func_HttpURLConnectionImpl_getRequestProperty.implementation = function (field) {
        var funcName = "HttpURLConnectionImpl.getRequestProperty"
        var funcParaDict = {
          "field": field,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retRequestProperty = this.getRequestProperty(field)
        if (isShowLog) {
          console.log(`${funcName} => retRequestProperty=${retRequestProperty}`)
        }
        return retRequestProperty
      }
    }

    // @Override public void setConnectTimeout(int timeoutMillis) {
    // public void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setConnectTimeout(int)
    var func_HttpURLConnectionImpl_setConnectTimeout = cls_HttpURLConnectionImpl.setConnectTimeout
    console.log("func_HttpURLConnectionImpl_setConnectTimeout=" + func_HttpURLConnectionImpl_setConnectTimeout)
    if (func_HttpURLConnectionImpl_setConnectTimeout) {
      func_HttpURLConnectionImpl_setConnectTimeout.implementation = function (timeoutMillis) {
        var funcName = "HttpURLConnectionImpl.setConnectTimeout"
        var funcParaDict = {
          "timeoutMillis": timeoutMillis,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setConnectTimeout(timeoutMillis)
        return
      }
    }

    // public void setInstanceFollowRedirects(boolean followRedirects) {
    // public void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setInstanceFollowRedirects(boolean)
    var func_HttpURLConnectionImpl_setInstanceFollowRedirects = cls_HttpURLConnectionImpl.setInstanceFollowRedirects
    console.log("func_HttpURLConnectionImpl_setInstanceFollowRedirects=" + func_HttpURLConnectionImpl_setInstanceFollowRedirects)
    if (func_HttpURLConnectionImpl_setInstanceFollowRedirects) {
      func_HttpURLConnectionImpl_setInstanceFollowRedirects.implementation = function (followRedirects) {
        var funcName = "HttpURLConnectionImpl.setInstanceFollowRedirects"
        var funcParaDict = {
          "followRedirects": followRedirects,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setInstanceFollowRedirects(followRedirects)
        return
      }
    }

    // @Override public boolean getInstanceFollowRedirects() {
    // public boolean com.android.okhttp.internal.huc.HttpURLConnectionImpl.getInstanceFollowRedirects()
    var func_HttpURLConnectionImpl_getInstanceFollowRedirects = cls_HttpURLConnectionImpl.getInstanceFollowRedirects
    console.log("func_HttpURLConnectionImpl_getInstanceFollowRedirects=" + func_HttpURLConnectionImpl_getInstanceFollowRedirects)
    if (func_HttpURLConnectionImpl_getInstanceFollowRedirects) {
      func_HttpURLConnectionImpl_getInstanceFollowRedirects.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getInstanceFollowRedirects"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var instanceFollowRedirects = this.getInstanceFollowRedirects()
        if (isShowLog) {
          console.log(`${funcName} => instanceFollowRedirects=${instanceFollowRedirects}`)
        }
        return instanceFollowRedirects
      }
    }

    // @Override public int getConnectTimeout() {
    // public int com.android.okhttp.internal.huc.HttpURLConnectionImpl.getConnectTimeout()
    var func_HttpURLConnectionImpl_getConnectTimeout = cls_HttpURLConnectionImpl.getConnectTimeout
    console.log("func_HttpURLConnectionImpl_getConnectTimeout=" + func_HttpURLConnectionImpl_getConnectTimeout)
    if (func_HttpURLConnectionImpl_getConnectTimeout) {
      func_HttpURLConnectionImpl_getConnectTimeout.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getConnectTimeout"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var connectTimeout = this.getConnectTimeout()
        if (isShowLog) {
          console.log(`${funcName} => connectTimeout=${connectTimeout}`)
        }
        return connectTimeout
      }
    }

    // @Override public void setReadTimeout(int timeoutMillis) {
    // public void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setReadTimeout(int)
    var func_HttpURLConnectionImpl_setReadTimeout = cls_HttpURLConnectionImpl.setReadTimeout
    console.log("func_HttpURLConnectionImpl_setReadTimeout=" + func_HttpURLConnectionImpl_setReadTimeout)
    if (func_HttpURLConnectionImpl_setReadTimeout) {
      func_HttpURLConnectionImpl_setReadTimeout.implementation = function (timeoutMillis) {
        var funcName = "HttpURLConnectionImpl.setReadTimeout"
        var funcParaDict = {
          "timeoutMillis": timeoutMillis,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setReadTimeout(timeoutMillis)
        return
      }
    }

    // @Override public int getReadTimeout() {
    // public int com.android.okhttp.internal.huc.HttpURLConnectionImpl.getReadTimeout()
    var func_HttpURLConnectionImpl_getReadTimeout = cls_HttpURLConnectionImpl.getReadTimeout
    console.log("func_HttpURLConnectionImpl_getReadTimeout=" + func_HttpURLConnectionImpl_getReadTimeout)
    if (func_HttpURLConnectionImpl_getReadTimeout) {
      func_HttpURLConnectionImpl_getReadTimeout.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getReadTimeout"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retReadTimeout = this.getReadTimeout()
        if (isShowLog) {
          console.log(`${funcName} => retReadTimeout=${retReadTimeout}`)
        }
        return retReadTimeout
      }
    }

    // private void initHttpEngine() throws IOException {
    // private void com.android.okhttp.internal.huc.HttpURLConnectionImpl.initHttpEngine() throws java.io.IOException
    var func_HttpURLConnectionImpl_initHttpEngine = cls_HttpURLConnectionImpl.initHttpEngine
    console.log("func_HttpURLConnectionImpl_initHttpEngine=" + func_HttpURLConnectionImpl_initHttpEngine)
    if (func_HttpURLConnectionImpl_initHttpEngine) {
      func_HttpURLConnectionImpl_initHttpEngine.implementation = function () {
        var funcName = "HttpURLConnectionImpl.initHttpEngine"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.initHttpEngine()
        return
      }
    }

    // private HttpEngine newHttpEngine(String method, StreamAllocation streamAllocation, RetryableSink requestBody, Response priorResponse) throws MalformedURLException, UnknownHostException {
    // private com.android.okhttp.internal.http.HttpEngine com.android.okhttp.internal.huc.HttpURLConnectionImpl.newHttpEngine(java.lang.String,com.android.okhttp.internal.http.StreamAllocation,com.android.okhttp.internal.http.RetryableSink,com.android.okhttp.Response) throws java.net.MalformedURLException,java.net.UnknownHostException
    var func_HttpURLConnectionImpl_newHttpEngine = cls_HttpURLConnectionImpl.newHttpEngine
    console.log("func_HttpURLConnectionImpl_newHttpEngine=" + func_HttpURLConnectionImpl_newHttpEngine)
    if (func_HttpURLConnectionImpl_newHttpEngine) {
      func_HttpURLConnectionImpl_newHttpEngine.implementation = function (method, streamAllocation, requestBody, priorResponse) {
        var funcName = "HttpURLConnectionImpl.newHttpEngine"
        var funcParaDict = {
          "method": method,
          "streamAllocation": streamAllocation,
          "requestBody": requestBody,
          "priorResponse": priorResponse,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHttpEngine = this.newHttpEngine(method, streamAllocation, requestBody, priorResponse)
        if (isShowLog) {
          console.log(`${funcName} => retHttpEngine=${retHttpEngine}`)
        }
        return retHttpEngine
      }
    }

    // private String defaultUserAgent() {
    // private java.lang.String com.android.okhttp.internal.huc.HttpURLConnectionImpl.defaultUserAgent()
    var func_HttpURLConnectionImpl_defaultUserAgent = cls_HttpURLConnectionImpl.defaultUserAgent
    console.log("func_HttpURLConnectionImpl_defaultUserAgent=" + func_HttpURLConnectionImpl_defaultUserAgent)
    if (func_HttpURLConnectionImpl_defaultUserAgent) {
      func_HttpURLConnectionImpl_defaultUserAgent.implementation = function () {
        var funcName = "HttpURLConnectionImpl.defaultUserAgent"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retString = this.defaultUserAgent()
        if (isShowLog) {
          console.log(`${funcName} => retString=${retString}`)
        }
        return retString
      }
    }

    // private HttpEngine getResponse() throws IOException {
    // private com.android.okhttp.internal.http.HttpEngine com.android.okhttp.internal.huc.HttpURLConnectionImpl.getResponse() throws java.io.IOException
    var func_HttpURLConnectionImpl_getResponse = cls_HttpURLConnectionImpl.getResponse
    console.log("func_HttpURLConnectionImpl_getResponse=" + func_HttpURLConnectionImpl_getResponse)
    if (func_HttpURLConnectionImpl_getResponse) {
      func_HttpURLConnectionImpl_getResponse.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getResponse"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var curHttpEngine = this.getResponse()
        if (isShowLog) {
          console.log(`${funcName} => curHttpEngine=${curHttpEngine}`)
        }

        // // var reqBodyOutStream = curHttpEngine.requestBodyOut.value
        // // console.log("reqBodyOutStream=" + reqBodyOutStream + ", clsName=" + FridaAndroidUtil.getJavaClassName(reqBodyOutStream))
        // // var reqBodyOutStream = this.requestBodyOut
        // var retryableSink = curHttpEngine.getRequestBody()
        // var clsName_RetryableSink = FridaAndroidUtil.getJavaClassName(retryableSink)
        // console.log("retryableSink=" + retryableSink + ", clsName=" + clsName_RetryableSink)
        // // retryableSink=[object Object], clsName=com.android.okhttp.internal.http.RetryableSink
        // // FridaAndroidUtil.printClassAllMethodsFields(clsName_RetryableSink)

        // var curRequest = curHttpEngine.getRequest()
        // console.log("curRequest=" + curRequest + ", clsName=" + FridaAndroidUtil.getJavaClassName(curRequest))

        // FridaAndroidUtil.printClass_RetryableSink(retryableSink)

        return curHttpEngine
      }
    }

    // private boolean execute(boolean readResponse) throws IOException {
    // private boolean com.android.okhttp.internal.huc.HttpURLConnectionImpl.execute(boolean) throws java.io.IOException
    var func_HttpURLConnectionImpl_execute = cls_HttpURLConnectionImpl.execute
    console.log("func_HttpURLConnectionImpl_execute=" + func_HttpURLConnectionImpl_execute)
    if (func_HttpURLConnectionImpl_execute) {
      func_HttpURLConnectionImpl_execute.implementation = function (readResponse) {
        var funcName = "HttpURLConnectionImpl.execute"
        var funcParaDict = {
          "readResponse": readResponse,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retBoolean = this.execute(readResponse)
        if (isShowLog) {
          console.log(`${funcName} => retBoolean=${retBoolean}`)
        }
        return retBoolean
      }
    }

    // @Override public final boolean usingProxy() {
    // public final boolean com.android.okhttp.internal.huc.HttpURLConnectionImpl.usingProxy()
    var func_HttpURLConnectionImpl_usingProxy = cls_HttpURLConnectionImpl.usingProxy
    console.log("func_HttpURLConnectionImpl_usingProxy=" + func_HttpURLConnectionImpl_usingProxy)
    if (func_HttpURLConnectionImpl_usingProxy) {
      func_HttpURLConnectionImpl_usingProxy.implementation = function () {
        var funcName = "HttpURLConnectionImpl.usingProxy"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retBoolean = this.usingProxy()
        if (isShowLog) {
          console.log(`${funcName} => retBoolean=${retBoolean}`)
        }
        return retBoolean
      }
    }

    // @Override public String getResponseMessage() throws IOException {
    // public java.lang.String com.android.okhttp.internal.huc.HttpURLConnectionImpl.getResponseMessage() throws java.io.IOException
    var func_HttpURLConnectionImpl_getResponseMessage = cls_HttpURLConnectionImpl.getResponseMessage
    console.log("func_HttpURLConnectionImpl_getResponseMessage=" + func_HttpURLConnectionImpl_getResponseMessage)
    if (func_HttpURLConnectionImpl_getResponseMessage) {
      func_HttpURLConnectionImpl_getResponseMessage.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getResponseMessage"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retResponseMessage = this.getResponseMessage()
        if (isShowLog) {
          console.log(`${funcName} => retResponseMessage=${retResponseMessage}`)
        }
        return retResponseMessage
      }
    }

    // @Override public final int getResponseCode() throws IOException {
    // public final int com.android.okhttp.internal.huc.HttpURLConnectionImpl.getResponseCode() throws java.io.IOException
    var func_HttpURLConnectionImpl_getResponseCode = cls_HttpURLConnectionImpl.getResponseCode
    console.log("func_HttpURLConnectionImpl_getResponseCode=" + func_HttpURLConnectionImpl_getResponseCode)
    if (func_HttpURLConnectionImpl_getResponseCode) {
      func_HttpURLConnectionImpl_getResponseCode.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getResponseCode"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        // FridaAndroidUtil.printClass_HttpOrHttpsURLConnectionImpl(this)
        var retResponseCode = this.getResponseCode()
        if (isShowLog) {
          console.log(`${funcName} => retResponseCode=${retResponseCode}`)
        }

        // // get request body data
        // var newBaos = FridaAndroidUtil.ByteArrayOutputStream.$new()
        // console.log("newBaos=" + newBaos + ", clsName=" + FridaAndroidUtil.getJavaClassName(newBaos))

        // // var reqBodyOutStream = this.getOutputStream()
        // // console.log("reqBodyOutStream=" + reqBodyOutStream + ", clsName=" + FridaAndroidUtil.getJavaClassName(reqBodyOutStream))
        // // newBaos.writeTo(reqBodyOutStream)

        // var reqBodyRbs = this.getOutputStream() // RealBufferedSink
        // console.log("reqBodyRbs=" + reqBodyRbs + ", clsName=" + FridaAndroidUtil.getJavaClassName(reqBodyRbs))

        // // var reqBodyRbsOutStream = reqBodyRbs.outputStream() // OutputStream
        // // console.log("reqBodyRbsOutStream=" + reqBodyRbsOutStream + ", clsName=" + FridaAndroidUtil.getJavaClassName(reqBodyRbsOutStream))
        // // newBaos.writeTo(reqBodyRbsOutStream)

        // var rbsSize = reqBodyRbs.size
        // console.log("rbsSize=" + rbsSize)
        // var rbsBuffer = reqBodyRbs.buffer
        // console.log("rbsBuffer=" + rbsBuffer + ", clsName=" + FridaAndroidUtil.getJavaClassName(rbsBuffer))

        // var okBufferSize = rbsBuffer.size
        // console.log("okBufferSize=" + okBufferSize)
        // var okBufferHead = rbsBuffer.head
        // console.log("okBufferHead=" + okBufferHead + ", clsName=" + FridaAndroidUtil.getJavaClassName(okBufferHead))

        // var reqBodyByteArr = newBaos.toByteArray()
        // console.log("reqBodyByteArr=" + reqBodyByteArr + ", clsName=" + FridaAndroidUtil.getJavaClassName(reqBodyByteArr))

        return retResponseCode
      }
    }

    // @Override public final void setRequestProperty(String field, String newValue) {
    // public final void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setRequestProperty(java.lang.String,java.lang.String)
    var func_HttpURLConnectionImpl_setRequestProperty = cls_HttpURLConnectionImpl.setRequestProperty
    console.log("func_HttpURLConnectionImpl_setRequestProperty=" + func_HttpURLConnectionImpl_setRequestProperty)
    if (func_HttpURLConnectionImpl_setRequestProperty) {
      func_HttpURLConnectionImpl_setRequestProperty.implementation = function (field, newValue) {
        var funcName = "HttpURLConnectionImpl.setRequestProperty"
        var funcParaDict = {
          "field": field,
          "newValue": newValue,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setRequestProperty(field, newValue)
        return
      }
    }

    // @Override public void setIfModifiedSince(long newValue) {
    // public void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setIfModifiedSince(long)
    var func_HttpURLConnectionImpl_setIfModifiedSince = cls_HttpURLConnectionImpl.setIfModifiedSince
    console.log("func_HttpURLConnectionImpl_setIfModifiedSince=" + func_HttpURLConnectionImpl_setIfModifiedSince)
    if (func_HttpURLConnectionImpl_setIfModifiedSince) {
      func_HttpURLConnectionImpl_setIfModifiedSince.implementation = function (newValue) {
        var funcName = "HttpURLConnectionImpl.setIfModifiedSince"
        var funcParaDict = {
          "newValue": newValue,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setIfModifiedSince(newValue)
        return
      }
    }

    // @Override public final void addRequestProperty(String field, String value) {
    // public final void com.android.okhttp.internal.huc.HttpURLConnectionImpl.addRequestProperty(java.lang.String,java.lang.String)
    var func_HttpURLConnectionImpl_addRequestProperty = cls_HttpURLConnectionImpl.addRequestProperty
    console.log("func_HttpURLConnectionImpl_addRequestProperty=" + func_HttpURLConnectionImpl_addRequestProperty)
    if (func_HttpURLConnectionImpl_addRequestProperty) {
      func_HttpURLConnectionImpl_addRequestProperty.implementation = function (field, value) {
        var funcName = "HttpURLConnectionImpl.addRequestProperty"
        var funcParaDict = {
          "field": field,
          "value": value,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.addRequestProperty(field, value)
        return
      }
    }

    // private void setProtocols(String protocolsString, boolean append) {
    // private void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setProtocols(java.lang.String,boolean)
    var func_HttpURLConnectionImpl_setProtocols = cls_HttpURLConnectionImpl.setProtocols
    console.log("func_HttpURLConnectionImpl_setProtocols=" + func_HttpURLConnectionImpl_setProtocols)
    if (func_HttpURLConnectionImpl_setProtocols) {
      func_HttpURLConnectionImpl_setProtocols.implementation = function (protocolsString, append) {
        var funcName = "HttpURLConnectionImpl.setProtocols"
        var funcParaDict = {
          "protocolsString": protocolsString,
          "append": append,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setProtocols(protocolsString, append)
        return
      }
    }

    // @Override public void setRequestMethod(String method) throws ProtocolException {
    // public void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setRequestMethod(java.lang.String) throws java.net.ProtocolException
    var func_HttpURLConnectionImpl_setRequestMethod = cls_HttpURLConnectionImpl.setRequestMethod
    console.log("func_HttpURLConnectionImpl_setRequestMethod=" + func_HttpURLConnectionImpl_setRequestMethod)
    if (func_HttpURLConnectionImpl_setRequestMethod) {
      func_HttpURLConnectionImpl_setRequestMethod.implementation = function (method) {
        var funcName = "HttpURLConnectionImpl.setRequestMethod"
        var funcParaDict = {
          "method": method,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setRequestMethod(method)
        return
      }
    }

    // @Override public void setFixedLengthStreamingMode(int contentLength) {
    // public void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setFixedLengthStreamingMode(int)
    var func_HttpURLConnectionImpl_setFixedLengthStreamingMode_i = cls_HttpURLConnectionImpl.setFixedLengthStreamingMode.overload("int")
    console.log("func_HttpURLConnectionImpl_setFixedLengthStreamingMode_i=" + func_HttpURLConnectionImpl_setFixedLengthStreamingMode_i)
    if (func_HttpURLConnectionImpl_setFixedLengthStreamingMode_i) {
      func_HttpURLConnectionImpl_setFixedLengthStreamingMode_i.implementation = function (contentLength) {
        var funcName = "HttpURLConnectionImpl.setFixedLengthStreamingMode(int)"
        var funcParaDict = {
          "contentLength": contentLength,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setFixedLengthStreamingMode(contentLength)
        return
      }
    }

    // @Override public void setFixedLengthStreamingMode(long contentLength) {
    // public void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setFixedLengthStreamingMode(long)
    var func_HttpURLConnectionImpl_setFixedLengthStreamingMode_l = cls_HttpURLConnectionImpl.setFixedLengthStreamingMode.overload("long")
    console.log("func_HttpURLConnectionImpl_setFixedLengthStreamingMode_l=" + func_HttpURLConnectionImpl_setFixedLengthStreamingMode_l)
    if (func_HttpURLConnectionImpl_setFixedLengthStreamingMode_l) {
      func_HttpURLConnectionImpl_setFixedLengthStreamingMode_l.implementation = function (contentLength) {
        var funcName = "HttpURLConnectionImpl.setFixedLengthStreamingMode"
        var funcParaDict = {
          "contentLength": contentLength,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setFixedLengthStreamingMode(contentLength)
        return
      }
    }
  }

  static HttpURLConnection(callback_isShowLog=null) {
    // FridaAndroidUtil.printClassAllMethodsFields(FridaAndroidUtil.clsName_HttpURLConnection)

    var cls_HttpURLConnection = Java.use(FridaAndroidUtil.clsName_HttpURLConnection)
    console.log("cls_HttpURLConnection=" + cls_HttpURLConnection)

    //var  curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    var curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // static boolean getFollowRedirects()
    // public static boolean java.net.HttpURLConnection.getFollowRedirects()
    var func_HttpURLConnection_getFollowRedirects = cls_HttpURLConnection.getFollowRedirects
    console.log("func_HttpURLConnection_getFollowRedirects=" + func_HttpURLConnection_getFollowRedirects)
    func_HttpURLConnection_getFollowRedirects.implementation = function () {
      var funcName = "HttpURLConnection.getFollowRedirects"
      var funcParaDict = {}
      curLogFunc(funcName, funcParaDict)
      // var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, FridaAndroidUtil.printFunctionCallAndStack, callback_isShowLog)
      var retFollowRedirects = this.getFollowRedirects()
      // if (isShowLog) {
        console.log(`${funcName} => retFollowRedirects=${retFollowRedirects}`)
      // }
      return retFollowRedirects
    }

    // abstract void disconnect()
    // public abstract void java.net.HttpURLConnection.disconnect()
    var func_HttpURLConnection_disconnect = cls_HttpURLConnection.disconnect
    console.log("func_HttpURLConnection_disconnect=" + func_HttpURLConnection_disconnect)
    if (func_HttpURLConnection_disconnect) {
      func_HttpURLConnection_disconnect.implementation = function () {
        var funcName = "HttpURLConnection.disconnect"
        var funcParaDict = {}
        // curLogFunc(funcName, funcParaDict)
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.disconnect()
        return
      }
    }

    // InputStream getErrorStream()
    // public java.io.InputStream java.net.HttpURLConnection.getErrorStream()
    var func_HttpURLConnection_getErrorStream = cls_HttpURLConnection.getErrorStream
    console.log("func_HttpURLConnection_getErrorStream=" + func_HttpURLConnection_getErrorStream)
    if (func_HttpURLConnection_getErrorStream) {
      func_HttpURLConnection_getErrorStream.implementation = function () {
        var funcName = "HttpURLConnection.getErrorStream"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retErrorStream = this.getErrorStream()
        if (isShowLog) {
          console.log(`${funcName} => retErrorStream=${retErrorStream}`)
        }
        return retErrorStream
      }
    }

    // String getHeaderField(int n)
    // public java.lang.String java.net.HttpURLConnection.getHeaderField(int)
    var func_HttpURLConnection_getHeaderField = cls_HttpURLConnection.getHeaderField
    console.log("func_HttpURLConnection_getHeaderField=" + func_HttpURLConnection_getHeaderField)
    if (func_HttpURLConnection_getHeaderField) {
      func_HttpURLConnection_getHeaderField.implementation = function (n) {
        var funcName = "HttpURLConnection.getHeaderField"
        var funcParaDict = {
          "n": n,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaderField = this.getHeaderField(n)
        if (isShowLog) {
          console.log(`${funcName} => retHeaderField=${retHeaderField}`)
        }
        return retHeaderField
      }
    }

    // long getHeaderFieldDate(String name, long Default)
    // public long java.net.HttpURLConnection.getHeaderFieldDate(java.lang.String,long)
    var func_HttpURLConnection_getHeaderFieldDate = cls_HttpURLConnection.getHeaderFieldDate
    console.log("func_HttpURLConnection_getHeaderFieldDate=" + func_HttpURLConnection_getHeaderFieldDate)
    if (func_HttpURLConnection_getHeaderFieldDate) {
      func_HttpURLConnection_getHeaderFieldDate.implementation = function (name, Default) {
        var funcName = "HttpURLConnection.getHeaderFieldDate"
        var funcParaDict = {
          "name": name,
          "Default": Default,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaderFieldDate = this.getHeaderFieldDate(name, Default)
        if (isShowLog) {
          console.log(`${funcName} => retHeaderFieldDate=${retHeaderFieldDate}`)
        }
        return retHeaderFieldDate
      }
    }

    // String getHeaderFieldKey(int n)
    // public java.lang.String java.net.HttpURLConnection.getHeaderFieldKey(int)
    var func_HttpURLConnection_getHeaderFieldKey = cls_HttpURLConnection.getHeaderFieldKey
    console.log("func_HttpURLConnection_getHeaderFieldKey=" + func_HttpURLConnection_getHeaderFieldKey)
    if (func_HttpURLConnection_getHeaderFieldKey) {
      func_HttpURLConnection_getHeaderFieldKey.implementation = function (n) {
        var funcName = "HttpURLConnection.getHeaderFieldKey"
        var funcParaDict = {
          "n": n,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaderFieldKey = this.getHeaderFieldKey(n)
        if (isShowLog) {
          console.log(`${funcName} => retHeaderFieldKey=${retHeaderFieldKey}`)
        }
        return retHeaderFieldKey
      }
    }

    // boolean getInstanceFollowRedirects()
    // public boolean java.net.HttpURLConnection.getInstanceFollowRedirects()
    var func_HttpURLConnection_getInstanceFollowRedirects = cls_HttpURLConnection.getInstanceFollowRedirects
    console.log("func_HttpURLConnection_getInstanceFollowRedirects=" + func_HttpURLConnection_getInstanceFollowRedirects)
    if (func_HttpURLConnection_getInstanceFollowRedirects) {
      func_HttpURLConnection_getInstanceFollowRedirects.implementation = function () {
        var funcName = "HttpURLConnection.getInstanceFollowRedirects"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retInstanceFollowRedirects = this.getInstanceFollowRedirects()
        if (isShowLog) {
          console.log(`${funcName} => retInstanceFollowRedirects=${retInstanceFollowRedirects}`)
        }
        return retInstanceFollowRedirects
      }
    }

    // Permission getPermission()
    // public java.security.Permission java.net.HttpURLConnection.getPermission() throws java.io.IOException
    var func_HttpURLConnection_getPermission = cls_HttpURLConnection.getPermission
    console.log("func_HttpURLConnection_getPermission=" + func_HttpURLConnection_getPermission)
    if (func_HttpURLConnection_getPermission) {
      func_HttpURLConnection_getPermission.implementation = function () {
        var funcName = "HttpURLConnection.getPermission"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retPermission = this.getPermission()
        if (isShowLog) {
          console.log(`${funcName} => retPermission=${retPermission}`)
        }
        return retPermission
      }
    }

    // String getRequestMethod()
    // public java.lang.String java.net.HttpURLConnection.getRequestMethod()
    var func_HttpURLConnection_getRequestMethod = cls_HttpURLConnection.getRequestMethod
    console.log("func_HttpURLConnection_getRequestMethod=" + func_HttpURLConnection_getRequestMethod)
    if (func_HttpURLConnection_getRequestMethod) {
      func_HttpURLConnection_getRequestMethod.implementation = function () {
        var funcName = "HttpURLConnection.getRequestMethod"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retRequestMethod = this.getRequestMethod()
        if (isShowLog) {
          console.log(`${funcName} => retRequestMethod=${retRequestMethod}`)
        }
        return retRequestMethod
      }
    }

    // int getResponseCode()
    // public int java.net.HttpURLConnection.getResponseCode() throws java.io.IOException
    var func_HttpURLConnection_getResponseCode = cls_HttpURLConnection.getResponseCode
    console.log("func_HttpURLConnection_getResponseCode=" + func_HttpURLConnection_getResponseCode)
    if (func_HttpURLConnection_getResponseCode) {
      func_HttpURLConnection_getResponseCode.implementation = function () {
        var funcName = "HttpURLConnection.getResponseCode"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, FridaAndroidUtil.printFunctionCallAndStack, callback_isShowLog)
        var respCode = this.getResponseCode()
        if(isShowLog) {
          console.log(`${funcName} => respCode=${respCode}`)
        }
        return respCode
      }
    }

    // String getResponseMessage()
    // public java.lang.String java.net.HttpURLConnection.getResponseMessage() throws java.io.IOException
    var func_HttpURLConnection_getResponseMessage = cls_HttpURLConnection.getResponseMessage
    console.log("func_HttpURLConnection_getResponseMessage=" + func_HttpURLConnection_getResponseMessage)
    if (func_HttpURLConnection_getResponseMessage) {
      func_HttpURLConnection_getResponseMessage.implementation = function () {
        var funcName = "HttpURLConnection.getResponseMessage"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retResponseMessage = this.getResponseMessage()
        if(isShowLog) {
          console.log(`${funcName} => retResponseMessage=${retResponseMessage}`)
        }
        return retResponseMessage
      }
    }

    // void setChunkedStreamingMode(int chunklen)
    // public void java.net.HttpURLConnection.setChunkedStreamingMode(int)
    var func_HttpURLConnection_setChunkedStreamingMode = cls_HttpURLConnection.setChunkedStreamingMode
    console.log("func_HttpURLConnection_setChunkedStreamingMode=" + func_HttpURLConnection_setChunkedStreamingMode)
    if (func_HttpURLConnection_setChunkedStreamingMode) {
      func_HttpURLConnection_setChunkedStreamingMode.implementation = function (chunklen) {
        var funcName = "HttpURLConnection.setChunkedStreamingMode"
        var funcParaDict = {
          "chunklen": chunklen,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setChunkedStreamingMode(chunklen)
        return
      }
    }

    // void setFixedLengthStreamingMode(int contentLength)
    // public void java.net.HttpURLConnection.setFixedLengthStreamingMode(int)
    var func_HttpURLConnection_setFixedLengthStreamingMode_1pi = cls_HttpURLConnection.setFixedLengthStreamingMode.overload("int")
    console.log("func_HttpURLConnection_setFixedLengthStreamingMode_1pi=" + func_HttpURLConnection_setFixedLengthStreamingMode_1pi)
    if (func_HttpURLConnection_setFixedLengthStreamingMode_1pi) {
      func_HttpURLConnection_setFixedLengthStreamingMode_1pi.implementation = function (contentLength) {
        var funcName = "HttpURLConnection.setFixedLengthStreamingMode(int)"
        var funcParaDict = {
          "contentLength": contentLength,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, FridaAndroidUtil.printFunctionCallAndStack, callback_isShowLog)
        this.setFixedLengthStreamingMode(contentLength)
        return
      }
    }

    // void setFixedLengthStreamingMode(long contentLength)
    // public void java.net.HttpURLConnection.setFixedLengthStreamingMode(long)
    var func_HttpURLConnection_setFixedLengthStreamingMode_1pl = cls_HttpURLConnection.setFixedLengthStreamingMode.overload("long")
    console.log("func_HttpURLConnection_setFixedLengthStreamingMode_1pl=" + func_HttpURLConnection_setFixedLengthStreamingMode_1pl)
    if (func_HttpURLConnection_setFixedLengthStreamingMode_1pl) {
      func_HttpURLConnection_setFixedLengthStreamingMode_1pl.implementation = function (contentLength) {
        var funcName = "HttpURLConnection.setFixedLengthStreamingMode(long)"
        var funcParaDict = {
          "contentLength": contentLength,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, FridaAndroidUtil.printFunctionCallAndStack, callback_isShowLog)
        this.setFixedLengthStreamingMode(contentLength)
        return
      }
    }

    // static void setFollowRedirects(boolean set)
    // public static void java.net.HttpURLConnection.setFollowRedirects(boolean)
    var func_HttpURLConnection_setFollowRedirects = cls_HttpURLConnection.setFollowRedirects
    console.log("func_HttpURLConnection_setFollowRedirects=" + func_HttpURLConnection_setFollowRedirects)
    func_HttpURLConnection_setFollowRedirects.implementation = function (set) {
      var funcName = "HttpURLConnection.setFollowRedirects"
      var funcParaDict = {
        "set": set,
      }
      curLogFunc(funcName, funcParaDict)
      // var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
      this.setFollowRedirects(set)
      return
    }

    // void setInstanceFollowRedirects(boolean followRedirects)
    // public void java.net.HttpURLConnection.setInstanceFollowRedirects(boolean)
    var func_HttpURLConnection_setInstanceFollowRedirects = cls_HttpURLConnection.setInstanceFollowRedirects
    console.log("func_HttpURLConnection_setInstanceFollowRedirects=" + func_HttpURLConnection_setInstanceFollowRedirects)
    if (func_HttpURLConnection_setInstanceFollowRedirects) {
      func_HttpURLConnection_setInstanceFollowRedirects.implementation = function (followRedirects) {
        var funcName = "HttpURLConnection.setInstanceFollowRedirects"
        var funcParaDict = {
          "followRedirects": followRedirects,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setInstanceFollowRedirects(followRedirects)
        return
      }
    }

    // void setRequestMethod(String method)
    // public void java.net.HttpURLConnection.setRequestMethod(java.lang.String) throws java.net.ProtocolException
    var func_HttpURLConnection_setRequestMethod = cls_HttpURLConnection.setRequestMethod
    console.log("func_HttpURLConnection_setRequestMethod=" + func_HttpURLConnection_setRequestMethod)
    if (func_HttpURLConnection_setRequestMethod) {
      func_HttpURLConnection_setRequestMethod.implementation = function (method) {
        var funcName = "HttpURLConnection.setRequestMethod"
        var funcParaDict = {
          "method": method,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, FridaAndroidUtil.printFunctionCallAndStack, callback_isShowLog)
        this.setRequestMethod(method)
        return
      }
    }

    // abstract boolean usingProxy()
    // public abstract boolean java.net.HttpURLConnection.usingProxy()
    var func_HttpURLConnection_usingProxy = cls_HttpURLConnection.usingProxy
    console.log("func_HttpURLConnection_usingProxy=" + func_HttpURLConnection_usingProxy)
    if (func_HttpURLConnection_usingProxy) {
      func_HttpURLConnection_usingProxy.implementation = function () {
        var funcName = "HttpURLConnection.usingProxy"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retBoolean = this.usingProxy()
        if(isShowLog) {
          console.log(`${funcName} => retBoolean=${retBoolean}`)
        }
        return retBoolean
      }
    }

  }


  static IOException() {
    var clsName_IOException = "java.io.IOException"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_IOException)

    var cls_IOException = Java.use(clsName_IOException)
    console.log("cls_IOException=" + cls_IOException)

    
    // IOException()
    // 
    var func_IOException_IOException_void = cls_IOException.$init.overload()
    console.log("func_IOException_IOException_void=" + func_IOException_IOException_void)
    if (func_IOException_IOException_void) {
      func_IOException_IOException_void.implementation = function () {
        var funcName = "IOException"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init()
        var newIOException_void = this
        console.log("IOException => newIOException_void=" + newIOException_void)
        return
      }
    }

    // IOException(String message)
    // 
    var func_IOException_IOException_1str = cls_IOException.$init.overload("java.lang.String")
    console.log("func_IOException_IOException_1str=" + func_IOException_IOException_1str)
    if (func_IOException_IOException_1str) {
      func_IOException_IOException_1str.implementation = function (message) {
        var funcName = "IOException(msg)"
        var funcParaDict = {
          "message": message,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(message)
        var newIOException_1str = this
        console.log("IOException(msg) => newIOException_1str=" + newIOException_1str)
        return
      }
    }

    // IOException(String message, Throwable cause)
    // 
    var func_IOException_IOException_2para = cls_IOException.$init.overload("java.lang.String", "java.lang.Throwable")
    console.log("func_IOException_IOException_2para=" + func_IOException_IOException_2para)
    if (func_IOException_IOException_2para) {
      func_IOException_IOException_2para.implementation = function (message, cause) {
        var funcName = "IOException(msg,cause)"
        var funcParaDict = {
          "message": message,
          "cause": cause,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(message, cause)
        var newIOException_2para = this
        console.log("IOException(msg,cause) => newIOException_2para=" + newIOException_2para)
        return
      }
    }

    // IOException(Throwable cause)
    // 
    var func_IOException_IOException_1t = cls_IOException.$init.overload("java.lang.Throwable")
    console.log("func_IOException_IOException_1t=" + func_IOException_IOException_1t)
    if (func_IOException_IOException_1t) {
      func_IOException_IOException_1t.implementation = function (cause) {
        var funcName = "IOException(cause)"
        var funcParaDict = {
          "cause": cause,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(cause)
        var newIOException_1t = this
        console.log("IOException(cause) => newIOException_1t=" + newIOException_1t)
        return
      }
    }
  }

  static Bundle() {
    var clsName_Bundle = "android.os.Bundle"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Bundle)

    var cls_Bundle = Java.use(clsName_Bundle)
    console.log("cls_Bundle=" + cls_Bundle)

    
    // Bundle()
    // 
    var func_Bundle_Bundle_0p = cls_Bundle.$init.overload()
    console.log("func_Bundle_Bundle_0p=" + func_Bundle_Bundle_0p)
    if (func_Bundle_Bundle_0p) {
      func_Bundle_Bundle_0p.implementation = function () {
        var funcName = "Bundle_0p"
        var funcParaDict = {}
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

        this.$init()
        var newBundle_0p = this
        console.log("Bundle_0p => newBundle_0p=" + newBundle_0p)
        return
      }
    }

    // Bundle(Bundle b)
    // Bundle(android.os.Bundle)
    var func_Bundle_Bundle_1pb = cls_Bundle.$init.overload("android.os.Bundle")
    console.log("func_Bundle_Bundle_1pb=" + func_Bundle_Bundle_1pb)
    if (func_Bundle_Bundle_1pb) {
      func_Bundle_Bundle_1pb.implementation = function (b) {
        var funcName = "Bundle_1pb"
        var funcParaDict = {
          "b": b,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(b)
        var newBundle_1pb = this
        console.log("Bundle_1pb => newBundle_1pb=" + newBundle_1pb)
        return
      }
    }

    // Bundle(PersistableBundle b)
    // Bundle(android.os.PersistableBundle)
    var func_Bundle_Bundle_1ppb = cls_Bundle.$init.overload("android.os.PersistableBundle")
    console.log("func_Bundle_Bundle_1ppb=" + func_Bundle_Bundle_1ppb)
    if (func_Bundle_Bundle_1ppb) {
      func_Bundle_Bundle_1ppb.implementation = function (b) {
        var funcName = "Bundle_1pb"
        var funcParaDict = {
          "b": b,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(b)
        var newBundle_1pb = this
        console.log("Bundle_1pb => newBundle_1pb=" + newBundle_1pb)
        return
      }
    }

    // Bundle(int capacity)
    // Bundle(int)
    var func_Bundle_Bundle_1pc = cls_Bundle.$init.overload("int")
    console.log("func_Bundle_Bundle_1pc=" + func_Bundle_Bundle_1pc)
    if (func_Bundle_Bundle_1pc) {
      func_Bundle_Bundle_1pc.implementation = function (capacity) {
        var funcName = "Bundle_1pc"
        var funcParaDict = {
          "capacity": capacity,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(capacity)
        var newBundle_1pc = this
        console.log("Bundle_1pc => newBundle_1pc=" + newBundle_1pc)
        return
      }
    }

    // Bundle(ClassLoader loader)
    // Bundle(java.lang.ClassLoader)
    var func_Bundle_Bundle_1pl = cls_Bundle.$init.overload("java.lang.ClassLoader")
    console.log("func_Bundle_Bundle_1pl=" + func_Bundle_Bundle_1pl)
    if (func_Bundle_Bundle_1pl) {
      func_Bundle_Bundle_1pl.implementation = function (loader) {
        var funcName = "Bundle_1pl"
        var funcParaDict = {
          "loader": loader,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(loader)
        var newBundle_1pl = this
        console.log("Bundle_1pl => newBundle_1pl=" + newBundle_1pl)
        return
      }
    }

    // Bundle getBundle(String key)
    // public android.os.Bundle android.os.Bundle.getBundle(java.lang.String)
    var func_Bundle_getBundle = cls_Bundle.getBundle
    console.log("func_Bundle_getBundle=" + func_Bundle_getBundle)
    if (func_Bundle_getBundle) {
      func_Bundle_getBundle.implementation = function (key) {
        var funcName = "Bundle.getBundle"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBundle = this.getBundle(key)
        console.log("Bundle.getBundle => retBundle=" + retBundle)
        return retBundle
      }
    }

    // IBinder getBinder(String key)
    // public android.os.IBinder android.os.Bundle.getBinder(java.lang.String)
    var func_Bundle_getBinder = cls_Bundle.getBinder
    console.log("func_Bundle_getBinder=" + func_Bundle_getBinder)
    if (func_Bundle_getBinder) {
      func_Bundle_getBinder.implementation = function (key) {
        var funcName = "Bundle.getBinder"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBinder = this.getBinder(key)
        console.log("Bundle.getBinder => retBinder=" + retBinder)
        return retBinder
      }
    }

    // <T extends Parcelable>T getParcelable(String key)
    // public android.os.Parcelable android.os.Bundle.getParcelable(java.lang.String)
    var func_Bundle_getParcelable_1pk = cls_Bundle.getParcelable.overload("java.lang.String")
    console.log("func_Bundle_getParcelable_1pk=" + func_Bundle_getParcelable_1pk)
    if (func_Bundle_getParcelable_1pk) {
      func_Bundle_getParcelable_1pk.implementation = function (key) {
        var funcName = "Bundle.getParcelable_1pk"
        var funcParaDict = {
          "key": key,
        }
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

        var retParcelable_1pk = this.getParcelable(key)
        console.log("Bundle.getParcelable_1pk => retParcelable_1pk=" + retParcelable_1pk)
        return retParcelable_1pk
      }
    }

    // <T>T getParcelable(String key, Class<T> clazz)
    // public java.lang.Object android.os.Bundle.getParcelable(java.lang.String,java.lang.Class)
    var func_Bundle_getParcelable_2pkc = cls_Bundle.getParcelable.overload("java.lang.String", "java.lang.Class")
    console.log("func_Bundle_getParcelable_2pkc=" + func_Bundle_getParcelable_2pkc)
    if (func_Bundle_getParcelable_2pkc) {
      func_Bundle_getParcelable_2pkc.implementation = function (key, clazz) {
        var funcName = "Bundle.getParcelable_2pkc"
        var funcParaDict = {
          "key": key,
          "clazz": clazz,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retParcelable_2pkc = this.getParcelable(key, clazz)
        console.log("Bundle.getParcelable_2pkc => retParcelable_2pkc=" + retParcelable_2pkc)
        return retParcelable_2pkc
      }
    }

    // Parcelable[] getParcelableArray(String key)
    // public android.os.Parcelable[] android.os.Bundle.getParcelableArray(java.lang.String)
    var func_Bundle_getParcelableArray_1pk = cls_Bundle.getParcelableArray.overload("java.lang.String")
    console.log("func_Bundle_getParcelableArray_1pk=" + func_Bundle_getParcelableArray_1pk)
    if (func_Bundle_getParcelableArray_1pk) {
      func_Bundle_getParcelableArray_1pk.implementation = function (key) {
        var funcName = "Bundle.getParcelableArray_1pk"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retParcelableArray_1pk = this.getParcelableArray(key)
        console.log("Bundle.getParcelableArray_1pk => retParcelableArray_1pk=" + retParcelableArray_1pk)
        return retParcelableArray_1pk
      }
    }

    // <T>T[] getParcelableArray(String key, Class<T> clazz)
    // public java.lang.Object[] android.os.Bundle.getParcelableArray(java.lang.String,java.lang.Class)
    var func_Bundle_getParcelableArray_2pkc = cls_Bundle.getParcelableArray.overload("java.lang.String", "java.lang.Class")
    console.log("func_Bundle_getParcelableArray_2pkc=" + func_Bundle_getParcelableArray_2pkc)
    if (func_Bundle_getParcelableArray_2pkc) {
      func_Bundle_getParcelableArray_2pkc.implementation = function (key, clazz) {
        var funcName = "Bundle.getParcelableArray_2pkc"
        var funcParaDict = {
          "key": key,
          "clazz": clazz,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retParcelableArray_2pkc = this.getParcelableArray(key, clazz)
        console.log("Bundle.getParcelableArray_2pkc => retParcelableArray_2pkc=" + retParcelableArray_2pkc)
        return retParcelableArray_2pkc
      }
    }

    // <T> ArrayList<T> getParcelableArrayList(String key, Class<? extends T> clazz)
    // public java.lang.Object android.os.Bundle.getParcelable(java.lang.String,java.lang.Class)
    var func_Bundle_getParcelableArrayList_2pkc = cls_Bundle.getParcelableArrayList.overload("java.lang.String", "java.lang.Class")
    console.log("func_Bundle_getParcelableArrayList_2pkc=" + func_Bundle_getParcelableArrayList_2pkc)
    if (func_Bundle_getParcelableArrayList_2pkc) {
      func_Bundle_getParcelableArrayList_2pkc.implementation = function (key, clazz) {
        var funcName = "Bundle.getParcelableArrayList_2pkc"
        var funcParaDict = {
          "key": key,
          "clazz": clazz,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retParcelableArrayList_2pkc = this.getParcelableArrayList(key, clazz)
        console.log("Bundle.getParcelableArrayList_2pkc => retParcelableArrayList_2pkc=" + retParcelableArrayList_2pkc)
        return retParcelableArrayList_2pkc
      }
    }

    // <T extends Parcelable> ArrayList<T> getParcelableArrayList(String key)
    // public java.util.ArrayList android.os.Bundle.getParcelableArrayList(java.lang.String)
    var func_Bundle_getParcelableArrayList_1pk = cls_Bundle.getParcelableArrayList.overload("java.lang.String")
    console.log("func_Bundle_getParcelableArrayList_1pk=" + func_Bundle_getParcelableArrayList_1pk)
    if (func_Bundle_getParcelableArrayList_1pk) {
      func_Bundle_getParcelableArrayList_1pk.implementation = function (key) {
        var funcName = "Bundle.getParcelableArrayList_1pk"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retParcelableArrayList_1pk = this.getParcelableArrayList(key)
        console.log("Bundle.getParcelableArrayList_1pk => retParcelableArrayList_1pk=" + retParcelableArrayList_1pk)
        return retParcelableArrayList_1pk
      }
    }

    // void putAll(Bundle bundle)
    // public void android.os.Bundle.putAll(android.os.Bundle)
    var func_Bundle_putAll = cls_Bundle.putAll
    console.log("func_Bundle_putAll=" + func_Bundle_putAll)
    if (func_Bundle_putAll) {
      func_Bundle_putAll.implementation = function (bundle) {
        var funcName = "Bundle.putAll"
        var funcParaDict = {
          "bundle": bundle,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putAll(bundle)
      }
    }

    // void putBinder(String key, IBinder value)
    // public void android.os.Bundle.putBinder(java.lang.String,android.os.IBinder)
    var func_Bundle_putBinder = cls_Bundle.putBinder
    console.log("func_Bundle_putBinder=" + func_Bundle_putBinder)
    if (func_Bundle_putBinder) {
      func_Bundle_putBinder.implementation = function (key, value) {
        var funcName = "Bundle.putBinder"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putBinder(key, value)
      }
    }

    // void putBundle(String key, Bundle value)
    // public void android.os.Bundle.putBundle(java.lang.String,android.os.Bundle)
    var func_Bundle_putBundle = cls_Bundle.putBundle
    console.log("func_Bundle_putBundle=" + func_Bundle_putBundle)
    if (func_Bundle_putBundle) {
      func_Bundle_putBundle.implementation = function (key, value) {
        var funcName = "Bundle.putBundle"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putBundle(key, value)
      }
    }

    // void putParcelable(String key, Parcelable value)
    // public void android.os.Bundle.putParcelable(java.lang.String,android.os.Parcelable)
    var func_Bundle_putParcelable = cls_Bundle.putParcelable
    console.log("func_Bundle_putParcelable=" + func_Bundle_putParcelable)
    if (func_Bundle_putParcelable) {
      func_Bundle_putParcelable.implementation = function (key, value) {
        var funcName = "Bundle.putParcelable"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

        return this.putParcelable(key, value)
      }
    }

    // void putParcelableArray(String key, Parcelable[] value)
    // public void android.os.Bundle.putParcelableArray(java.lang.String,android.os.Parcelable[])
    var func_Bundle_putParcelableArray = cls_Bundle.putParcelableArray
    console.log("func_Bundle_putParcelableArray=" + func_Bundle_putParcelableArray)
    if (func_Bundle_putParcelableArray) {
      func_Bundle_putParcelableArray.implementation = function (key, value) {
        var funcName = "Bundle.putParcelableArray"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putParcelableArray(key, value)
      }
    }

    // void putParcelableArrayList(String key, ArrayList<? extends Parcelable> value)
    // public void android.os.Bundle.putParcelableArrayList(java.lang.String,java.util.ArrayList)
    var func_Bundle_putParcelableArrayList = cls_Bundle.putParcelableArrayList
    console.log("func_Bundle_putParcelableArrayList=" + func_Bundle_putParcelableArrayList)
    if (func_Bundle_putParcelableArrayList) {
      func_Bundle_putParcelableArrayList.implementation = function (key, value) {
        var funcName = "Bundle.putParcelableArrayList"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putParcelableArrayList(key, value)
      }
    }

    // void putSparseParcelableArray(String key, SparseArray<? extends Parcelable> value)
    // public void android.os.Bundle.putSparseParcelableArray(java.lang.String,android.util.SparseArray)
    var func_Bundle_putSparseParcelableArray = cls_Bundle.putSparseParcelableArray
    console.log("func_Bundle_putSparseParcelableArray=" + func_Bundle_putSparseParcelableArray)
    if (func_Bundle_putSparseParcelableArray) {
      func_Bundle_putSparseParcelableArray.implementation = function (key, value) {
        var funcName = "Bundle.putSparseParcelableArray"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putSparseParcelableArray(key, value)
      }
    }

    // void readFromParcel(Parcel parcel)
    // public void android.os.Bundle.readFromParcel(android.os.Parcel)
    var func_Bundle_readFromParcel = cls_Bundle.readFromParcel
    console.log("func_Bundle_readFromParcel=" + func_Bundle_readFromParcel)
    if (func_Bundle_readFromParcel) {
      func_Bundle_readFromParcel.implementation = function (parcel) {
        var funcName = "Bundle.readFromParcel"
        var funcParaDict = {
          "parcel": parcel,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.readFromParcel(parcel)
      }
    }

    // void writeToParcel(Parcel parcel, int flags)
    // public void android.os.Bundle.writeToParcel(android.os.Parcel,int)
    var func_Bundle_writeToParcel = cls_Bundle.writeToParcel
    console.log("func_Bundle_writeToParcel=" + func_Bundle_writeToParcel)
    if (func_Bundle_writeToParcel) {
      func_Bundle_writeToParcel.implementation = function (parcel, flags) {
        var funcName = "Bundle.writeToParcel"
        var funcParaDict = {
          "parcel": parcel,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.writeToParcel(parcel, flags)
      }
    }

    // void remove(String key)
    // public void android.os.Bundle.remove(java.lang.String)
    var func_Bundle_remove = cls_Bundle.remove
    console.log("func_Bundle_remove=" + func_Bundle_remove)
    if (func_Bundle_remove) {
      func_Bundle_remove.implementation = function (key) {
        var funcName = "Bundle.remove"
        var funcParaDict = {
          "key": key,
        }
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

        return this.remove(key)
      }
    }

  }

  static BaseBundle() {
    var clsName_BaseBundle = "android.os.BaseBundle"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_BaseBundle)

    var cls_BaseBundle = Java.use(clsName_BaseBundle)
    console.log("cls_BaseBundle=" + cls_BaseBundle)

    // const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    const curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // boolean containsKey(String key)
    // public boolean android.os.BaseBundle.containsKey(java.lang.String)
    var func_BaseBundle_containsKey = cls_BaseBundle.containsKey
    console.log("func_BaseBundle_containsKey=" + func_BaseBundle_containsKey)
    if (func_BaseBundle_containsKey) {
      func_BaseBundle_containsKey.implementation = function (key) {
        var funcName = "BaseBundle.containsKey"
        var funcParaDict = {
          "key": key,
        }
        curLogFunc(funcName, funcParaDict)

        var retBoolean = this.containsKey(key)
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // boolean getBoolean(String key, boolean defaultValue)
    // public boolean android.os.BaseBundle.getBoolean(java.lang.String,boolean)
    var func_BaseBundle_getBoolean_2pkd = cls_BaseBundle.getBoolean.overload("java.lang.String", "boolean")
    console.log("func_BaseBundle_getBoolean_2pkd=" + func_BaseBundle_getBoolean_2pkd)
    if (func_BaseBundle_getBoolean_2pkd) {
      func_BaseBundle_getBoolean_2pkd.implementation = function (key, defaultValue) {
        var funcName = "BaseBundle.getBoolean_2pkd"
        var funcParaDict = {
          "key": key,
          "defaultValue": defaultValue,
        }
        curLogFunc(funcName, funcParaDict)

        var retBoolean_2pkd = this.getBoolean(key, defaultValue)
        console.log(funcName + " => retBoolean_2pkd=" + retBoolean_2pkd)
        return retBoolean_2pkd
      }
    }

    // boolean getBoolean(String key)
    // public boolean android.os.BaseBundle.getBoolean(java.lang.String)
    var func_BaseBundle_getBoolean_1pk = cls_BaseBundle.getBoolean.overload("java.lang.String")
    console.log("func_BaseBundle_getBoolean_1pk=" + func_BaseBundle_getBoolean_1pk)
    if (func_BaseBundle_getBoolean_1pk) {
      func_BaseBundle_getBoolean_1pk.implementation = function (key) {
        var funcName = "BaseBundle.getBoolean_1pk"
        var funcParaDict = {
          "key": key,
        }
        curLogFunc(funcName, funcParaDict)

        var retBoolean_1pk = this.getBoolean(key)
        console.log(funcName + " => retBoolean_1pk=" + retBoolean_1pk)
        return retBoolean_1pk
      }
    }

    // void putAll(PersistableBundle bundle)
    // public void android.os.BaseBundle.putAll(android.os.PersistableBundle)
    var func_BaseBundle_putAll_1pb = cls_BaseBundle.putAll.overload("android.os.PersistableBundle")
    console.log("func_BaseBundle_putAll_1pb=" + func_BaseBundle_putAll_1pb)
    if (func_BaseBundle_putAll_1pb) {
      func_BaseBundle_putAll_1pb.implementation = function (bundle) {
        var funcName = "BaseBundle.putAll_1pb"
        var funcParaDict = {
          "bundle": bundle,
        }
        curLogFunc(funcName, funcParaDict)

        return this.putAll(bundle)
      }
    }

    // void putAll(ArrayMap map)
    // void android.os.BaseBundle.putAll(android.util.ArrayMap)
    var func_BaseBundle_putAll_1pm = cls_BaseBundle.putAll.overload("android.util.ArrayMap")
    console.log("func_BaseBundle_putAll_1pm=" + func_BaseBundle_putAll_1pm)
    if (func_BaseBundle_putAll_1pm) {
      func_BaseBundle_putAll_1pm.implementation = function (map) {
        var funcName = "BaseBundle.putAll_1pm"
        var funcParaDict = {
          "map": map,
        }
        curLogFunc(funcName, funcParaDict)

        return this.putAll(map)
      }
    }

    // void putBoolean(String key, boolean value)
    // public void android.os.BaseBundle.putBoolean(java.lang.String,boolean)
    var func_BaseBundle_putBoolean = cls_BaseBundle.putBoolean
    console.log("func_BaseBundle_putBoolean=" + func_BaseBundle_putBoolean)
    if (func_BaseBundle_putBoolean) {
      func_BaseBundle_putBoolean.implementation = function (key, value) {
        var funcName = "BaseBundle.putBoolean"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)

        return this.putBoolean(key, value)
      }
    }

    // void putBooleanArray(String key, boolean[] value)
    // public void android.os.BaseBundle.putBooleanArray(java.lang.String,boolean[])
    var func_BaseBundle_putBooleanArray = cls_BaseBundle.putBooleanArray
    console.log("func_BaseBundle_putBooleanArray=" + func_BaseBundle_putBooleanArray)
    if (func_BaseBundle_putBooleanArray) {
      func_BaseBundle_putBooleanArray.implementation = function (key, value) {
        var funcName = "BaseBundle.putBooleanArray"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)

        return this.putBooleanArray(key, value)
      }
    }

    // void putDouble(String key, double value)
    // public void android.os.BaseBundle.putDouble(java.lang.String,double)
    var func_BaseBundle_putDouble = cls_BaseBundle.putDouble
    console.log("func_BaseBundle_putDouble=" + func_BaseBundle_putDouble)
    if (func_BaseBundle_putDouble) {
      func_BaseBundle_putDouble.implementation = function (key, value) {
        var funcName = "BaseBundle.putDouble"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)

        return this.putDouble(key, value)
      }
    }

    // void putDoubleArray(String key, double[] value)
    // public void android.os.BaseBundle.putDoubleArray(java.lang.String,double[])
    var func_BaseBundle_putDoubleArray = cls_BaseBundle.putDoubleArray
    console.log("func_BaseBundle_putDoubleArray=" + func_BaseBundle_putDoubleArray)
    if (func_BaseBundle_putDoubleArray) {
      func_BaseBundle_putDoubleArray.implementation = function (key, value) {
        var funcName = "BaseBundle.putDoubleArray"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)

        return this.putDoubleArray(key, value)
      }
    }

    // void putInt(String key, int value)
    // public void android.os.BaseBundle.putInt(java.lang.String,int)
    var func_BaseBundle_putInt = cls_BaseBundle.putInt
    console.log("func_BaseBundle_putInt=" + func_BaseBundle_putInt)
    if (func_BaseBundle_putInt) {
      func_BaseBundle_putInt.implementation = function (key, value) {
        var funcName = "BaseBundle.putInt"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)

        return this.putInt(key, value)
      }
    }

    // void putIntArray(String key, int[] value)
    // public void android.os.BaseBundle.putIntArray(java.lang.String,int[])
    var func_BaseBundle_putIntArray = cls_BaseBundle.putIntArray
    console.log("func_BaseBundle_putIntArray=" + func_BaseBundle_putIntArray)
    if (func_BaseBundle_putIntArray) {
      func_BaseBundle_putIntArray.implementation = function (key, value) {
        var funcName = "BaseBundle.putIntArray"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)

        return this.putIntArray(key, value)
      }
    }

    // void putLong(String key, long value)
    // public void android.os.BaseBundle.putLong(java.lang.String,long)
    var func_BaseBundle_putLong = cls_BaseBundle.putLong
    console.log("func_BaseBundle_putLong=" + func_BaseBundle_putLong)
    if (func_BaseBundle_putLong) {
      func_BaseBundle_putLong.implementation = function (key, value) {
        var funcName = "BaseBundle.putLong"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)

        return this.putLong(key, value)
      }
    }

    // void putLongArray(String key, long[] value)
    // public void android.os.BaseBundle.putLongArray(java.lang.String,long[])
    var func_BaseBundle_putLongArray = cls_BaseBundle.putLongArray
    console.log("func_BaseBundle_putLongArray=" + func_BaseBundle_putLongArray)
    if (func_BaseBundle_putLongArray) {
      func_BaseBundle_putLongArray.implementation = function (key, value) {
        var funcName = "BaseBundle.putLongArray"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)

        return this.putLongArray(key, value)
      }
    }

    // void putString(String key, String value)
    // public void android.os.BaseBundle.putString(java.lang.String,java.lang.String)
    var func_BaseBundle_putString = cls_BaseBundle.putString
    console.log("func_BaseBundle_putString=" + func_BaseBundle_putString)
    if (func_BaseBundle_putString) {
      func_BaseBundle_putString.implementation = function (key, value) {
        var funcName = "BaseBundle.putString"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)

        return this.putString(key, value)
      }
    }

    // void putStringArray(String key, String[] value)
    // public void android.os.BaseBundle.putStringArray(java.lang.String,java.lang.String[])
    var func_BaseBundle_putStringArray = cls_BaseBundle.putStringArray
    console.log("func_BaseBundle_putStringArray=" + func_BaseBundle_putStringArray)
    if (func_BaseBundle_putStringArray) {
      func_BaseBundle_putStringArray.implementation = function (key, value) {
        var funcName = "BaseBundle.putStringArray"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)

        return this.putStringArray(key, value)
      }
    }

    // void remove(String key)
    // public void android.os.BaseBundle.remove(java.lang.String)
    var func_BaseBundle_remove = cls_BaseBundle.remove
    console.log("func_BaseBundle_remove=" + func_BaseBundle_remove)
    if (func_BaseBundle_remove) {
      func_BaseBundle_remove.implementation = function (key) {
        var funcName = "BaseBundle.remove"
        var funcParaDict = {
          "key": key,
        }
        curLogFunc(funcName, funcParaDict)

        return this.remove(key)
      }
    }

    // Object get(String key)
    // public java.lang.Object android.os.BaseBundle.get(java.lang.String)
    var func_BaseBundle_get_1pk = cls_BaseBundle.get.overload("java.lang.String")
    console.log("func_BaseBundle_get_1pk=" + func_BaseBundle_get_1pk)
    if (func_BaseBundle_get_1pk) {
      func_BaseBundle_get_1pk.implementation = function (key) {
        var funcName = "BaseBundle.get_1pk"
        var funcParaDict = {
          "key": key,
        }
        curLogFunc(funcName, funcParaDict)

        var retObject_1pk = this.get(key)
        console.log("BaseBundle.get_1pk => retObject_1pk=" + retObject_1pk)
        return retObject_1pk
      }
    }

    // <T>T get(String key, Class<T> clazz)
    // java.lang.Object android.os.BaseBundle.get(java.lang.String,java.lang.Class)
    var func_BaseBundle_get_2pkc = cls_BaseBundle.get.overload("java.lang.String", "java.lang.Class")
    console.log("func_BaseBundle_get_2pkc=" + func_BaseBundle_get_2pkc)
    if (func_BaseBundle_get_2pkc) {
      func_BaseBundle_get_2pkc.implementation = function (key, clazz) {
        var funcName = "BaseBundle.get_2pkc"
        var funcParaDict = {
          "key": key,
          "clazz": clazz,
        }
        curLogFunc(funcName, funcParaDict)

        var ret_T_T_2pkc = this.get(key, clazz)
        console.log(funcName + " => ret_T_T_2pkc=" + ret_T_T_2pkc)
        return ret_T_T_2pkc
      }
    }

    // int getInt(String key)
    // public int android.os.BaseBundle.getInt(java.lang.String)
    var func_BaseBundle_getInt_1pk = cls_BaseBundle.getInt.overload("java.lang.String")
    console.log("func_BaseBundle_getInt_1pk=" + func_BaseBundle_getInt_1pk)
    if (func_BaseBundle_getInt_1pk) {
      func_BaseBundle_getInt_1pk.implementation = function (key) {
        var funcName = "BaseBundle.getInt(key)"
        var funcParaDict = {
          "key": key,
        }
        curLogFunc(funcName, funcParaDict)
        // FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

        var retInt_1pk = this.getInt(key)
        console.log(funcName + " => retInt_1pk=" + retInt_1pk)
        return retInt_1pk
      }
    }

    // int getInt(String key, int defaultValue)
    // public int android.os.BaseBundle.getInt(java.lang.String,int)
    var func_BaseBundle_getInt_2pkd = cls_BaseBundle.getInt.overload("java.lang.String", "int")
    console.log("func_BaseBundle_getInt_2pkd=" + func_BaseBundle_getInt_2pkd)
    if (func_BaseBundle_getInt_2pkd) {
      func_BaseBundle_getInt_2pkd.implementation = function (key, defaultValue) {
        var funcName = "BaseBundle.getInt(key,defaultValue)"
        var funcParaDict = {
          "key": key,
          "defaultValue": defaultValue,
        }
        curLogFunc(funcName, funcParaDict)

        var retInt_2pkd = this.getInt(key, defaultValue)
        console.log(funcName + " => retInt_2pkd=" + retInt_2pkd)
        return retInt_2pkd
      }
    }

    // String getString(String key)
    // public java.lang.String android.os.BaseBundle.getString(java.lang.String)
    var func_BaseBundle_getString_1pk = cls_BaseBundle.getString.overload("java.lang.String")
    console.log("func_BaseBundle_getString_1pk=" + func_BaseBundle_getString_1pk)
    if (func_BaseBundle_getString_1pk) {
      func_BaseBundle_getString_1pk.implementation = function (key) {
        var funcName = "BaseBundle.getString_1pk"
        var funcParaDict = {
          "key": key,
        }
        curLogFunc(funcName, funcParaDict)

        var retString_1pk = this.getString(key)
        console.log(funcName + " => retString_1pk=" + retString_1pk)
        return retString_1pk
      }
    }

    // String getString(String key, String defaultValue)
    // public java.lang.String android.os.BaseBundle.getString(java.lang.String,java.lang.String)
    var func_BaseBundle_getString_2pkd = cls_BaseBundle.getString.overload("java.lang.String", "java.lang.String")
    console.log("func_BaseBundle_getString_2pkd=" + func_BaseBundle_getString_2pkd)
    if (func_BaseBundle_getString_2pkd) {
      func_BaseBundle_getString_2pkd.implementation = function (key, defaultValue) {
        var funcName = "BaseBundle.getString_2pkd"
        var funcParaDict = {
          "key": key,
          "defaultValue": defaultValue,
        }
        curLogFunc(funcName, funcParaDict)

        var retString_2pkd = this.getString(key, defaultValue)
        console.log(funcName + " => retString_2pkd=" + retString_2pkd)
        return retString_2pkd
      }
    }

    // String[] getStringArray(String key)
    // public java.lang.String[] android.os.BaseBundle.getStringArray(java.lang.String)
    var func_BaseBundle_getStringArray = cls_BaseBundle.getStringArray
    console.log("func_BaseBundle_getStringArray=" + func_BaseBundle_getStringArray)
    if (func_BaseBundle_getStringArray) {
      func_BaseBundle_getStringArray.implementation = function (key) {
        var funcName = "BaseBundle.getStringArray"
        var funcParaDict = {
          "key": key,
        }
        curLogFunc(funcName, funcParaDict)

        var retStringArray = this.getStringArray(key)
        console.log(funcName + " => retStringArray=" + retStringArray)
        return retStringArray
      }
    }

  }

  static Messenger() {
    var clsName_Messenger = "android.os.Messenger"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Messenger)

    var cls_Messenger = Java.use(clsName_Messenger)
    console.log("cls_Messenger=" + cls_Messenger)

    
    // Messenger(Handler target)
    // 
    var func_Messenger_Messenger_1ph = cls_Messenger.$init.overload('android.os.Handler')
    console.log("func_Messenger_Messenger_1ph=" + func_Messenger_Messenger_1ph)
    if (func_Messenger_Messenger_1ph) {
      func_Messenger_Messenger_1ph.implementation = function (targetHandler) {
        var funcName = "Messenger(Handler)"
        var funcParaDict = {
          "targetHandler": targetHandler,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(targetHandler)
        var newMessenger_1ph = this
        console.log("Messenger(Handler) => newMessenger_1ph=" + newMessenger_1ph)
        return
      }
    }

    // Messenger(IBinder target)
    // 
    var func_Messenger_Messenger_1pi = cls_Messenger.$init.overload('android.os.IBinder')
    console.log("func_Messenger_Messenger_1pi=" + func_Messenger_Messenger_1pi)
    if (func_Messenger_Messenger_1pi) {
      func_Messenger_Messenger_1pi.implementation = function (targetIBinder) {
        var funcName = "Messenger(IBinder)"
        var funcParaDict = {
          "targetIBinder": targetIBinder,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(targetIBinder)
        var newMessenger_1pi = this
        console.log("Messenger(IBinder) => newMessenger_1pi=" + newMessenger_1pi)
        return
      }
    }

    // int describeContents()
    // public int android.os.Messenger.describeContents()
    var func_Messenger_describeContents = cls_Messenger.describeContents
    console.log("func_Messenger_describeContents=" + func_Messenger_describeContents)
    if (func_Messenger_describeContents) {
      func_Messenger_describeContents.implementation = function () {
        var funcName = "Messenger.describeContents"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInt = this.describeContents()
        console.log("Messenger.describeContents => retInt=" + retInt)
        return retInt
      }
    }

    // boolean equals(Object otherObj)
    // public boolean android.os.Messenger.equals(java.lang.Object)
    var func_Messenger_equals = cls_Messenger.equals
    console.log("func_Messenger_equals=" + func_Messenger_equals)
    if (func_Messenger_equals) {
      func_Messenger_equals.implementation = function (otherObj) {
        var funcName = "Messenger.equals"
        var funcParaDict = {
          "otherObj": otherObj,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.equals(otherObj)
        console.log("Messenger.equals => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // IBinder getBinder()
    // public android.os.IBinder android.os.Messenger.getBinder()
    var func_Messenger_getBinder = cls_Messenger.getBinder
    console.log("func_Messenger_getBinder=" + func_Messenger_getBinder)
    if (func_Messenger_getBinder) {
      func_Messenger_getBinder.implementation = function () {
        var funcName = "Messenger.getBinder"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBinder = this.getBinder()
        console.log("Messenger.getBinder => retBinder=" + retBinder)
        return retBinder
      }
    }

    // int hashCode()
    // public int android.os.Messenger.hashCode()
    var func_Messenger_hashCode = cls_Messenger.hashCode
    console.log("func_Messenger_hashCode=" + func_Messenger_hashCode)
    if (func_Messenger_hashCode) {
      func_Messenger_hashCode.implementation = function () {
        var funcName = "Messenger.hashCode"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInt = this.hashCode()
        console.log("Messenger.hashCode => retInt=" + retInt)
        return retInt
      }
    }

    // static Messenger readMessengerOrNullFromParcel(Parcel inParcel)
    // public static android.os.Messenger android.os.Messenger.readMessengerOrNullFromParcel(android.os.Parcel)
    var func_Messenger_readMessengerOrNullFromParcel = cls_Messenger.readMessengerOrNullFromParcel
    console.log("func_Messenger_readMessengerOrNullFromParcel=" + func_Messenger_readMessengerOrNullFromParcel)
    if (func_Messenger_readMessengerOrNullFromParcel) {
      func_Messenger_readMessengerOrNullFromParcel.implementation = function (inParcel) {
        var funcName = "Messenger.readMessengerOrNullFromParcel"
        var funcParaDict = {
          "inParcel": inParcel,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retMessenger = this.readMessengerOrNullFromParcel(inParcel)
        console.log("Messenger.readMessengerOrNullFromParcel => retMessenger=" + retMessenger)
        return retMessenger
      }
    }

    // void send(Message message)
    // public void android.os.Messenger.send(android.os.Message) throws android.os.RemoteException
    var func_Messenger_send = cls_Messenger.send
    console.log("func_Messenger_send=" + func_Messenger_send)
    if (func_Messenger_send) {
      func_Messenger_send.implementation = function (message) {
        var funcName = "Messenger.send"
        var funcParaDict = {
          "message": message,
        }
        FridaAndroidUtil.printClass_Message(message, funcName)
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)


        return this.send(message)
      }
    }

    // static void writeMessengerOrNullToParcel(Messenger messenger, Parcel out)
    // public static void android.os.Messenger.writeMessengerOrNullToParcel(android.os.Messenger,android.os.Parcel)
    var func_Messenger_writeMessengerOrNullToParcel = cls_Messenger.writeMessengerOrNullToParcel
    console.log("func_Messenger_writeMessengerOrNullToParcel=" + func_Messenger_writeMessengerOrNullToParcel)
    if (func_Messenger_writeMessengerOrNullToParcel) {
      func_Messenger_writeMessengerOrNullToParcel.implementation = function (messenger, out) {
        var funcName = "Messenger.writeMessengerOrNullToParcel"
        var funcParaDict = {
          "messenger": messenger,
          "out": out,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.writeMessengerOrNullToParcel(messenger, out)
      }
    }

    // void writeToParcel(Parcel out, int flags)
    // public void android.os.Messenger.writeToParcel(android.os.Parcel,int)
    var func_Messenger_writeToParcel = cls_Messenger.writeToParcel
    console.log("func_Messenger_writeToParcel=" + func_Messenger_writeToParcel)
    if (func_Messenger_writeToParcel) {
      func_Messenger_writeToParcel.implementation = function (out, flags) {
        var funcName = "Messenger.writeToParcel"
        var funcParaDict = {
          "out": out,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.writeToParcel(out, flags)
      }
    }
  }

  static Message() {
    var clsName_Message = "android.os.Message"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Message)

    var cls_Message = Java.use(clsName_Message)
    console.log("cls_Message=" + cls_Message)

    
    // Message()
    // 
    var func_Message_Message = cls_Message.$init
    console.log("func_Message_Message=" + func_Message_Message)
    if (func_Message_Message) {
      func_Message_Message.implementation = function () {
        var funcName = "Message"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init()
        var newMessage = this
        console.log(funcName + " => newMessage=" + newMessage)
        return
      }
    }

    // static Message    obtain()
    // public static android.os.Message android.os.Message.obtain()
    var func_Message_obtain_0p = cls_Message.obtain.overload()
    console.log("func_Message_obtain_0p=" + func_Message_obtain_0p)
    if (func_Message_obtain_0p) {
      func_Message_obtain_0p.implementation = function () {
        var funcName = "Message.obtain_0p"
        var funcParaDict = {}
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

        var retMessage_0p = this.obtain()
        console.log(funcName + " => retMessage_0p=" + retMessage_0p)
        return retMessage_0p
      }
    }

    // void    setData(Bundle data)
    // public void android.os.Message.setData(android.os.Bundle)
    var func_Message_setData = cls_Message.setData
    console.log("func_Message_setData=" + func_Message_setData)
    if (func_Message_setData) {
      func_Message_setData.implementation = function (data) {
        var funcName = "Message.setData"
        var funcParaDict = {
          "data": data,
        }
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

        return this.setData(data)
      }
    }

    // Bundle    getData()
    // public android.os.Bundle android.os.Message.getData()
    var func_Message_getData = cls_Message.getData
    console.log("func_Message_getData=" + func_Message_getData)
    if (func_Message_getData) {
      func_Message_getData.implementation = function () {
        var funcName = "Message.getData"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retData = this.getData()
        console.log(funcName + " => retData=" + retData)
        return retData
      }
    }

    // void    writeToParcel(Parcel dest, int flags)
    // public void android.os.Message.writeToParcel(android.os.Parcel,int)
    var func_Message_writeToParcel = cls_Message.writeToParcel
    console.log("func_Message_writeToParcel=" + func_Message_writeToParcel)
    if (func_Message_writeToParcel) {
      func_Message_writeToParcel.implementation = function (dest, flags) {
        var funcName = "Message.writeToParcel"
        var funcParaDict = {
          "dest": dest,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.writeToParcel(dest, flags)
      }
    }
  }

  static Intent(callback_isShowLog=null) {
    var clsName_Intent = "android.content.Intent"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Intent)

    var cls_Intent = Java.use(clsName_Intent)
    console.log("cls_Intent=" + cls_Intent)


    // public Intent()
    // 
    var func_Intent_Intent_0p = cls_Intent.$init.overload()
    console.log("func_Intent_Intent_0p=" + func_Intent_Intent_0p)
    if (func_Intent_Intent_0p) {
      func_Intent_Intent_0p.implementation = function () {
        var funcName = "Intent_0p"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init()
        var newIntent_0p = this
        console.log(funcName + " => newIntent_0p=" + newIntent_0p)
        return
      }
    }

    // public Intent(String action)
    // 
    var func_Intent_Intent_1pa = cls_Intent.$init.overload("java.lang.String")
    console.log("func_Intent_Intent_1pa=" + func_Intent_Intent_1pa)
    if (func_Intent_Intent_1pa) {
      func_Intent_Intent_1pa.implementation = function (action) {
        var funcName = "Intent_1pa"
        var funcParaDict = {
          "action": action,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(action)
        var newIntent_1pa = this
        console.log(funcName + " => newIntent_1pa=" + newIntent_1pa)
        return
      }
    }

    // public Intent(String action, Uri uri)
    // 
    var func_Intent_Intent_2pau = cls_Intent.$init.overload("java.lang.String", "android.net.Uri")
    console.log("func_Intent_Intent_2pau=" + func_Intent_Intent_2pau)
    if (func_Intent_Intent_2pau) {
      func_Intent_Intent_2pau.implementation = function (action, uri) {
        var funcName = "Intent_2pau"
        var funcParaDict = {
          "action": action,
          "uri": uri,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(action, uri)
        var newIntent_2pau = this
        console.log(funcName + " => newIntent_2pau=" + newIntent_2pau)
        return
      }
    }

    // Intent setPackage(String packageName)
    // public android.content.Intent android.content.Intent.setPackage(java.lang.String)
    var func_Intent_setPackage = cls_Intent.setPackage
    console.log("func_Intent_setPackage=" + func_Intent_setPackage)
    if (func_Intent_setPackage) {
      func_Intent_setPackage.implementation = function (packageName) {
        var funcName = "Intent.setPackage"
        var funcParaDict = {
          "packageName": packageName,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retIntent = this.setPackage(packageName)
        console.log(funcName + " => retIntent=" + retIntent)
        return retIntent
      }
    }

    // Intent setAction(String action)
    // public android.content.Intent android.content.Intent.setAction(java.lang.String)
    var func_Intent_setAction = cls_Intent.setAction
    console.log("func_Intent_setAction=" + func_Intent_setAction)
    if (func_Intent_setAction) {
      func_Intent_setAction.implementation = function (action) {
        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(action)
        }

        if (isShowLog){
          var funcName = "Intent.setAction"
          var funcParaDict = {
            "action": action,
          }
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        } else {
          FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)
        }

        var retIntent = this.setAction(action)
        console.log("Intent.setAction => retIntent=" + retIntent)
        return retIntent
      }
    }

    // Intent putExtras(Intent srcIntent)
    // public android.content.Intent android.content.Intent.putExtras(android.content.Intent)
    var func_Intent_putExtras_1ps = cls_Intent.putExtras.overload("android.content.Intent")
    console.log("func_Intent_putExtras_1ps=" + func_Intent_putExtras_1ps)
    if (func_Intent_putExtras_1ps) {
      func_Intent_putExtras_1ps.implementation = function (srcIntent) {
        var funcName = "Intent.putExtras_1ps"
        var funcParaDict = {
          "srcIntent": srcIntent,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retIntent_1ps = this.putExtras(srcIntent)
        console.log("Intent.putExtras_1ps => retIntent_1ps=" + retIntent_1ps)
        return retIntent_1ps
      }
    }

    // Intent putExtras(Bundle extrasBundle)
    // public android.content.Intent android.content.Intent.putExtras(android.os.Bundle)
    var func_Intent_putExtras_1pe = cls_Intent.putExtras.overload("android.os.Bundle")
    console.log("func_Intent_putExtras_1pe=" + func_Intent_putExtras_1pe)
    if (func_Intent_putExtras_1pe) {
      func_Intent_putExtras_1pe.implementation = function (extrasBundle) {
        var funcName = "Intent.putExtras_1pe"
        var funcParaDict = {
          "extrasBundle": extrasBundle,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retIntent_1pe = this.putExtras(extrasBundle)
        console.log("Intent.putExtras_1pe => retIntent_1pe=" + retIntent_1pe)
        return retIntent_1pe
      }
    }

    // Intent putExtra(String name, Parcelable value)
    // public android.content.Intent android.content.Intent.putExtra(java.lang.String,android.os.Parcelable)
    var func_Intent_putExtra_2pnv = cls_Intent.putExtra.overload("java.lang.String", "android.os.Parcelable")
    console.log("func_Intent_putExtra_2pnv=" + func_Intent_putExtra_2pnv)
    if (func_Intent_putExtra_2pnv) {
      func_Intent_putExtra_2pnv.implementation = function (name, value) {
        var funcName = "Intent.putExtra_2pnv"
        var funcParaDict = {
          "name": name,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retIntent_2pnv = this.putExtra(name, value)
        console.log("Intent.putExtra_2pnv => retIntent_2pnv=" + retIntent_2pnv)
        return retIntent_2pnv
      }
    }

    // Intent putExtra(String name, String value)
    // public android.content.Intent android.content.Intent.putExtra(java.lang.String,java.lang.String)
    var func_Intent_putExtra_2pnv = cls_Intent.putExtra.overload("java.lang.String", "java.lang.String")
    console.log("func_Intent_putExtra_2pnv=" + func_Intent_putExtra_2pnv)
    if (func_Intent_putExtra_2pnv) {
      func_Intent_putExtra_2pnv.implementation = function (name, value) {
        var funcName = "Intent.putExtra_2pnv"
        var funcParaDict = {
          "name": name,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retIntent_2pnv = this.putExtra(name, value)
        console.log("Intent.putExtra_2pnv => retIntent_2pnv=" + retIntent_2pnv)
        return retIntent_2pnv
      }
    }

    // Bundle getExtras()
    // public android.os.Bundle android.content.Intent.getExtras()
    var func_Intent_getExtras = cls_Intent.getExtras
    console.log("func_Intent_getExtras=" + func_Intent_getExtras)
    if (func_Intent_getExtras) {
      func_Intent_getExtras.implementation = function () {
        var funcName = "Intent.getExtras"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retExtras = this.getExtras()
        console.log("Intent.getExtras => retExtras=" + retExtras)
        return retExtras
      }
    }

    // String getStringExtra(String name)
    // public java.lang.String android.content.Intent.getStringExtra(java.lang.String)
    var func_Intent_getStringExtra = cls_Intent.getStringExtra
    console.log("func_Intent_getStringExtra=" + func_Intent_getStringExtra)
    if (func_Intent_getStringExtra) {
      func_Intent_getStringExtra.implementation = function (name) {
        var funcName = "Intent.getStringExtra"
        var funcParaDict = {
          "name": name,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retStringExtra = this.getStringExtra(name)
        console.log("Intent.getStringExtra => retStringExtra=" + retStringExtra)
        return retStringExtra
      }
    }

    // String getAction()
    // public java.lang.String android.content.Intent.getAction()
    var func_Intent_getAction = cls_Intent.getAction
    console.log("func_Intent_getAction=" + func_Intent_getAction)
    if (func_Intent_getAction) {
      func_Intent_getAction.implementation = function () {
        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(action)
        }

        if (isShowLog){
          var funcName = "Intent.getAction"
          var funcParaDict = {}
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
          } else {
          FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)
        }

        var retAction = this.getAction()
        console.log("Intent.getAction => retAction=" + retAction)
        return retAction
      }
    }

  }

  static Handler(callback_isShowLog=null) {
    var clsName_Handler = "android.os.Handler"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Handler)

    var cls_Handler = Java.use(clsName_Handler)
    console.log("cls_Handler=" + cls_Handler)

    
    // void dispatchMessage(Message msg)
    // 
    var func_Handler_dispatchMessage = cls_Handler.dispatchMessage
    console.log("func_Handler_dispatchMessage=" + func_Handler_dispatchMessage)
    if (func_Handler_dispatchMessage) {
      func_Handler_dispatchMessage.implementation = function (msg) {
        var funcName = "Handler.dispatchMessage"
        var funcParaDict = {
          "msg": msg,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        return this.dispatchMessage(msg)
      }
    }

    // String getMessageName(Message message)
    // 
    var func_Handler_getMessageName = cls_Handler.getMessageName
    console.log("func_Handler_getMessageName=" + func_Handler_getMessageName)
    if (func_Handler_getMessageName) {
      func_Handler_getMessageName.implementation = function (message) {
        var funcName = "Handler.getMessageName"
        var funcParaDict = {
          "message": message,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retMessageName = this.getMessageName(message)
        if (isShowLog) {
          console.log("Handler.getMessageName => retMessageName=" + retMessageName)
        }
        return retMessageName
      }
    }

    // void handleMessage(Message msg)
    // 
    var func_Handler_handleMessage = cls_Handler.handleMessage
    console.log("func_Handler_handleMessage=" + func_Handler_handleMessage)
    if (func_Handler_handleMessage) {
      func_Handler_handleMessage.implementation = function (msg) {
        var funcName = "Handler.handleMessage"
        var funcParaDict = {
          "msg": msg,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        return this.handleMessage(msg)
      }
    }

    // final boolean sendMessage(Message msg)
    // 
    var func_Handler_sendMessage = cls_Handler.sendMessage
    console.log("func_Handler_sendMessage=" + func_Handler_sendMessage)
    if (func_Handler_sendMessage) {
      func_Handler_sendMessage.implementation = function (msg) {
        var funcName = "Handler.sendMessage"
        var funcParaDict = {
          "msg": msg,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retBoolean = this.sendMessage(msg)
        if (isShowLog) {
          console.log("Handler.sendMessage => retBoolean=" + retBoolean)
        }
        return retBoolean
      }
    }

    // final boolean sendMessageAtFrontOfQueue(Message msg)
    // 
    var func_Handler_sendMessageAtFrontOfQueue = cls_Handler.sendMessageAtFrontOfQueue
    console.log("func_Handler_sendMessageAtFrontOfQueue=" + func_Handler_sendMessageAtFrontOfQueue)
    if (func_Handler_sendMessageAtFrontOfQueue) {
      func_Handler_sendMessageAtFrontOfQueue.implementation = function (msg) {
        var funcName = "Handler.sendMessageAtFrontOfQueue"
        var funcParaDict = {
          "msg": msg,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retBoolean = this.sendMessageAtFrontOfQueue(msg)
        if (isShowLog) {
          console.log("Handler.sendMessageAtFrontOfQueue => retBoolean=" + retBoolean)
        }
        return retBoolean
      }
    }

    // boolean sendMessageAtTime(Message msg, long uptimeMillis)
    // 
    var func_Handler_sendMessageAtTime = cls_Handler.sendMessageAtTime
    console.log("func_Handler_sendMessageAtTime=" + func_Handler_sendMessageAtTime)
    if (func_Handler_sendMessageAtTime) {
      func_Handler_sendMessageAtTime.implementation = function (msg, uptimeMillis) {
        var funcName = "Handler.sendMessageAtTime"
        var funcParaDict = {
          "msg": msg,
          "uptimeMillis": uptimeMillis,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retBoolean = this.sendMessageAtTime(msg, uptimeMillis)
        if (isShowLog) {
          console.log("Handler.sendMessageAtTime => retBoolean=" + retBoolean)
        }
        return retBoolean
      }
    }

    // final boolean sendMessageDelayed(Message msg, long delayMillis)
    // 
    var func_Handler_sendMessageDelayed = cls_Handler.sendMessageDelayed
    console.log("func_Handler_sendMessageDelayed=" + func_Handler_sendMessageDelayed)
    if (func_Handler_sendMessageDelayed) {
      func_Handler_sendMessageDelayed.implementation = function (msg, delayMillis) {
        var funcName = "Handler.sendMessageDelayed"
        var funcParaDict = {
          "msg": msg,
          "delayMillis": delayMillis,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retBoolean = this.sendMessageDelayed(msg, delayMillis)
        if (isShowLog) {
          console.log("Handler.sendMessageDelayed => retBoolean=" + retBoolean)
        }
        return retBoolean
      }
    }

    // final Message obtainMessage(int what, Object obj)
    // public final android.os.Message android.os.Handler.obtainMessage(int,java.lang.Object)
    var func_Handler_obtainMessage_2pwo = cls_Handler.obtainMessage.overload("int", "java.lang.Object")
    console.log("func_Handler_obtainMessage_2pwo=" + func_Handler_obtainMessage_2pwo)
    if (func_Handler_obtainMessage_2pwo) {
      func_Handler_obtainMessage_2pwo.implementation = function (what, obj) {
        var funcName = "Handler.obtainMessage_2pwo"
        var funcParaDict = {
          "what": what,
          "obj": obj,
        }
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retMessage_2pwo = this.obtainMessage(what, obj)
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retMessage_2pwo=${retMessage_2pwo}`)
        return retMessage_2pwo
      }
    }

    // final Message obtainMessage()
    // public final android.os.Message android.os.Handler.obtainMessage()
    var func_Handler_obtainMessage_0p = cls_Handler.obtainMessage.overload()
    console.log("func_Handler_obtainMessage_0p=" + func_Handler_obtainMessage_0p)
    if (func_Handler_obtainMessage_0p) {
      func_Handler_obtainMessage_0p.implementation = function () {
        var funcName = "Handler.obtainMessage_0p"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retMessage_0p = this.obtainMessage()
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retMessage_0p=${retMessage_0p}`)
        return retMessage_0p
      }
    }

    // final Message obtainMessage(int what, int arg1, int arg2)
    // public final android.os.Message android.os.Handler.obtainMessage(int,int,int)
    var func_Handler_obtainMessage_3pwaa = cls_Handler.obtainMessage.overload("int", "int", "int")
    console.log("func_Handler_obtainMessage_3pwaa=" + func_Handler_obtainMessage_3pwaa)
    if (func_Handler_obtainMessage_3pwaa) {
      func_Handler_obtainMessage_3pwaa.implementation = function (what, arg1, arg2) {
        var funcName = "Handler.obtainMessage_3pwaa"
        var funcParaDict = {
          "what": what,
          "arg1": arg1,
          "arg2": arg2,
        }
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retMessage_3pwaa = this.obtainMessage(what, arg1, arg2)
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retMessage_3pwaa=${retMessage_3pwaa}`)
        return retMessage_3pwaa
      }
    }

    // final Message obtainMessage(int what, int arg1, int arg2, Object obj)
    // public final android.os.Message android.os.Handler.obtainMessage(int,int,int,java.lang.Object)
    var func_Handler_obtainMessage_4pwaao = cls_Handler.obtainMessage.overload("int", "int", "int", "java.lang.Object")
    console.log("func_Handler_obtainMessage_4pwaao=" + func_Handler_obtainMessage_4pwaao)
    if (func_Handler_obtainMessage_4pwaao) {
      func_Handler_obtainMessage_4pwaao.implementation = function (what, arg1, arg2, obj) {
        var funcName = "Handler.obtainMessage_4pwaao"
        var funcParaDict = {
          "what": what,
          "arg1": arg1,
          "arg2": arg2,
          "obj": obj,
        }
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retMessage_4pwaao = this.obtainMessage(what, arg1, arg2, obj)
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retMessage_4pwaao=${retMessage_4pwaao}`)
        return retMessage_4pwaao
      }
    }

    // final Message obtainMessage(int what)
    // public final android.os.Message android.os.Handler.obtainMessage(int)
    var func_Handler_obtainMessage_1pw = cls_Handler.obtainMessage.overload("int")
    console.log("func_Handler_obtainMessage_1pw=" + func_Handler_obtainMessage_1pw)
    if (func_Handler_obtainMessage_1pw) {
      func_Handler_obtainMessage_1pw.implementation = function (what) {
        var funcName = "Handler.obtainMessage_1pw"
        var funcParaDict = {
          "what": what,
        }
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retMessage_1pw = this.obtainMessage(what)
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retMessage_1pw=${retMessage_1pw}`)
        return retMessage_1pw
      }
    }

  }

  static Uri_Builder(callback_isShowLog=null) {
    var clsName_Uri_Builder = "android.net.Uri$Builder"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Uri_Builder)

    var cls_Uri_Builder = Java.use(clsName_Uri_Builder)
    console.log("cls_Uri_Builder=" + cls_Uri_Builder)

    // public Uri build()
    // public android.net.Uri android.net.Uri$Builder.build()
    var func_Uri_Builder_build = cls_Uri_Builder.build
    console.log("func_Uri_Builder_build=" + func_Uri_Builder_build)
    if (func_Uri_Builder_build) {
      func_Uri_Builder_build.implementation = function () {
        var funcName = "Uri$Builder.build"
        var funcParaDict = {}
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        var retUri = this.build()
        if (isShowLog) {
          console.log(funcName + " => retUri=" + retUri)
        }
        return retUri
      }
    }

    // public Uri.Builder appendQueryParameter(String key, String value)
    // public android.net.Uri$Builder android.net.Uri$Builder.appendQueryParameter(java.lang.String,java.lang.String)
    var func_Uri_Builder_appendQueryParameter = cls_Uri_Builder.appendQueryParameter
    console.log("func_Uri_Builder_appendQueryParameter=" + func_Uri_Builder_appendQueryParameter)
    if (func_Uri_Builder_appendQueryParameter) {
      func_Uri_Builder_appendQueryParameter.implementation = function (key, value) {
        var funcName = "Uri$Builder.appendQueryParameter"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        var retUri_Builder = this.appendQueryParameter(key, value)
        if (isShowLog) {
          console.log(funcName + " => retUri_Builder=" + retUri_Builder)
        }
        return retUri_Builder
      }
    }

  }

  static Uri(callback_isShowLog=null) {
    var clsName_Uri = "android.net.Uri"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Uri)

    var cls_Uri = Java.use(clsName_Uri)
    console.log("cls_Uri=" + cls_Uri)

    // public abstract String getPath()
    // public abstract java.lang.String android.net.Uri.getPath()
    var func_Uri_getPath = cls_Uri.getPath
    console.log("func_Uri_getPath=" + func_Uri_getPath)
    if (func_Uri_getPath) {
      func_Uri_getPath.implementation = function () {
        var funcName = "Uri.getPath"
        var funcParaDict = {}
        // var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retPath = this.getPath()
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retPath=${retPath}`)
        return retPath
      }
    }

    // public abstract String getAuthority()
    // public abstract java.lang.String android.net.Uri.getAuthority()
    var func_Uri_getAuthority = cls_Uri.getAuthority
    console.log("func_Uri_getAuthority=" + func_Uri_getAuthority)
    if (func_Uri_getAuthority) {
      func_Uri_getAuthority.implementation = function () {
        var funcName = "Uri.getAuthority"
        var funcParaDict = {}
        // var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        var retAuthority = this.getAuthority()
        // if (isShowLog) {
          console.log(funcName + " => retAuthority=" + retAuthority)
        // }
        return retAuthority
      }
    }

    // public abstract String getEncodedQuery()
    // public abstract java.lang.String android.net.Uri.getEncodedQuery()
    var func_Uri_getEncodedQuery = cls_Uri.getEncodedQuery
    console.log("func_Uri_getEncodedQuery=" + func_Uri_getEncodedQuery)
    if (func_Uri_getEncodedQuery) {
      func_Uri_getEncodedQuery.implementation = function () {
        var funcName = "Uri.getEncodedQuery"
        var funcParaDict = {}
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        var retEncodedQuery = this.getEncodedQuery()
        if (isShowLog) {
          console.log(funcName + " => retEncodedQuery=" + retEncodedQuery)
        }
        return retEncodedQuery
      }
    }

    // public static Uri parse(String uriString)
    // public static android.net.Uri android.net.Uri.parse(java.lang.String)
    var func_Uri_parse = cls_Uri.parse
    console.log("func_Uri_parse=" + func_Uri_parse)
    if (func_Uri_parse) {
      func_Uri_parse.implementation = function (uriString) {
        var funcName = "Uri.parse"
        var funcParaDict = {
          "uriString": uriString,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        var retUri = this.parse(uriString)
        // if (isShowLog) {
          console.log(funcName + " => retUri=" + retUri)
        // }
        return retUri
      }
    }

  }

  static CronetUrlRequest_origCode(cls_CronetUrlRequest) {
    // https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/cronet/android/java/src/org/chromium/net/impl/CronetUrlRequest.java

    /* CronetUrlRequest(
            CronetUrlRequestContext requestContext,
            String url,
            int priority,
            UrlRequest.Callback callback,
            Executor executor,
            Collection<Object> requestAnnotations,
            boolean disableCache,
            boolean disableConnectionMigration,
            boolean allowDirectExecutor,
            boolean trafficStatsTagSet,
            int trafficStatsTag,
            boolean trafficStatsUidSet,
            int trafficStatsUid,
            RequestFinishedInfo.Listener requestFinishedListener,
            int idempotency,
            long networkHandle,
            String method,
            ArrayList<Map.Entry<String, String>> requestHeaders,
            UploadDataProvider uploadDataProvider,
            Executor uploadDataProviderExecutor,
            byte[] dictionarySha256Hash,
            ByteBuffer dictionary,
            @NonNull String dictionaryId) {
    */
    // 
    var func_CronetUrlRequest_ctor = cls_CronetUrlRequest.$init
    console.log("func_CronetUrlRequest_ctor=" + func_CronetUrlRequest_ctor)
    if (func_CronetUrlRequest_ctor) {
      func_CronetUrlRequest_ctor.implementation = function (requestContext, url, priority, callback, executor, requestAnnotations, disableCache, disableConnectionMigration, allowDirectExecutor, trafficStatsTagSet, trafficStatsTag, trafficStatsUidSet, trafficStatsUid, requestFinishedListener, idempotency, networkHandle, method, requestHeaders, uploadDataProvider, uploadDataProviderExecutor, dictionarySha256Hash, dictionary, dictionaryId) {
        var funcName = "CronetUrlRequest"
        var funcParaDict = {
          "requestContext": requestContext,
          "url": url,
          "priority": priority,
          "callback": callback,
          "executor": executor,
          "requestAnnotations": requestAnnotations,
          "disableCache": disableCache,
          "disableConnectionMigration": disableConnectionMigration,
          "allowDirectExecutor": allowDirectExecutor,
          "trafficStatsTagSet": trafficStatsTagSet,
          "trafficStatsTag": trafficStatsTag,
          "trafficStatsUidSet": trafficStatsUidSet,
          "trafficStatsUid": trafficStatsUid,
          "requestFinishedListener": requestFinishedListener,
          "idempotency": idempotency,
          "networkHandle": networkHandle,
          "method": method,
          "requestHeaders": requestHeaders,
          "uploadDataProvider": uploadDataProvider,
          "uploadDataProviderExecutor": uploadDataProviderExecutor,
          "dictionarySha256Hash": dictionarySha256Hash,
          "dictionary": dictionary,
          "dictionaryId": dictionaryId,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(requestContext, url, priority, callback, executor, requestAnnotations, disableCache, disableConnectionMigration, allowDirectExecutor, trafficStatsTagSet, trafficStatsTag, trafficStatsUidSet, trafficStatsUid, requestFinishedListener, idempotency, networkHandle, method, requestHeaders, uploadDataProvider, uploadDataProviderExecutor, dictionarySha256Hash, dictionary, dictionaryId)
        var newCronetUrlRequest = this
        console.log(funcName + " => newCronetUrlRequest=" + newCronetUrlRequest)
        return
      }
    }

    // public void start() {
    // 
    var func_CronetUrlRequest_start = cls_CronetUrlRequest.start
    console.log("func_CronetUrlRequest_start=" + func_CronetUrlRequest_start)
    if (func_CronetUrlRequest_start) {
      func_CronetUrlRequest_start.implementation = function () {
        var funcName = "CronetUrlRequest.start"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.start()
      }
    }

    // private void startInternalLocked() {
    // 
    var func_CronetUrlRequest_startInternalLocked = cls_CronetUrlRequest.startInternalLocked
    console.log("func_CronetUrlRequest_startInternalLocked=" + func_CronetUrlRequest_startInternalLocked)
    if (func_CronetUrlRequest_startInternalLocked) {
      func_CronetUrlRequest_startInternalLocked.implementation = function () {
        var funcName = "CronetUrlRequest.startInternalLocked"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.startInternalLocked()
      }
    }

    // public void followRedirect() {
    // 
    var func_CronetUrlRequest_followRedirect = cls_CronetUrlRequest.followRedirect
    console.log("func_CronetUrlRequest_followRedirect=" + func_CronetUrlRequest_followRedirect)
    if (func_CronetUrlRequest_followRedirect) {
      func_CronetUrlRequest_followRedirect.implementation = function () {
        var funcName = "CronetUrlRequest.followRedirect"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.followRedirect()
      }
    }

    // public void read(ByteBuffer buffer) {
    // 
    var func_CronetUrlRequest_read = cls_CronetUrlRequest.read
    console.log("func_CronetUrlRequest_read=" + func_CronetUrlRequest_read)
    if (func_CronetUrlRequest_read) {
      func_CronetUrlRequest_read.implementation = function (buffer) {
        var funcName = "CronetUrlRequest.read"
        var funcParaDict = {
          "buffer": buffer,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.read(buffer)
      }
    }

    // public void cancel() {
    // 
    var func_CronetUrlRequest_cancel = cls_CronetUrlRequest.cancel
    console.log("func_CronetUrlRequest_cancel=" + func_CronetUrlRequest_cancel)
    if (func_CronetUrlRequest_cancel) {
      func_CronetUrlRequest_cancel.implementation = function () {
        var funcName = "CronetUrlRequest.cancel"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.cancel()
      }
    }

    // public boolean isDone() {
    // 
    var func_CronetUrlRequest_isDone = cls_CronetUrlRequest.isDone
    console.log("func_CronetUrlRequest_isDone=" + func_CronetUrlRequest_isDone)
    if (func_CronetUrlRequest_isDone) {
      func_CronetUrlRequest_isDone.implementation = function () {
        var funcName = "CronetUrlRequest.isDone"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.isDone()
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // private boolean isDoneLocked() {
    // 
    var func_CronetUrlRequest_isDoneLocked = cls_CronetUrlRequest.isDoneLocked
    console.log("func_CronetUrlRequest_isDoneLocked=" + func_CronetUrlRequest_isDoneLocked)
    if (func_CronetUrlRequest_isDoneLocked) {
      func_CronetUrlRequest_isDoneLocked.implementation = function () {
        var funcName = "CronetUrlRequest.isDoneLocked"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.isDoneLocked()
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // public void getStatus(UrlRequest.StatusListener unsafeListener) {
    // 
    var func_CronetUrlRequest_getStatus = cls_CronetUrlRequest.getStatus
    console.log("func_CronetUrlRequest_getStatus=" + func_CronetUrlRequest_getStatus)
    if (func_CronetUrlRequest_getStatus) {
      func_CronetUrlRequest_getStatus.implementation = function (unsafeListener) {
        var funcName = "CronetUrlRequest.getStatus"
        var funcParaDict = {
          "unsafeListener": unsafeListener,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.getStatus(unsafeListener)
      }
    }

    // public void setOnDestroyedCallbackForTesting(Runnable onDestroyedCallbackForTesting) {
    // 
    var func_CronetUrlRequest_setOnDestroyedCallbackForTesting = cls_CronetUrlRequest.setOnDestroyedCallbackForTesting
    console.log("func_CronetUrlRequest_setOnDestroyedCallbackForTesting=" + func_CronetUrlRequest_setOnDestroyedCallbackForTesting)
    if (func_CronetUrlRequest_setOnDestroyedCallbackForTesting) {
      func_CronetUrlRequest_setOnDestroyedCallbackForTesting.implementation = function (onDestroyedCallbackForTesting) {
        var funcName = "CronetUrlRequest.setOnDestroyedCallbackForTesting"
        var funcParaDict = {
          "onDestroyedCallbackForTesting": onDestroyedCallbackForTesting,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setOnDestroyedCallbackForTesting(onDestroyedCallbackForTesting)
      }
    }

    /* public void setOnDestroyedUploadCallbackForTesting(
            Runnable onDestroyedUploadCallbackForTesting) {
    */
    // 
    var func_CronetUrlRequest_setOnDestroyedUploadCallbackForTesting = cls_CronetUrlRequest.setOnDestroyedUploadCallbackForTesting
    console.log("func_CronetUrlRequest_setOnDestroyedUploadCallbackForTesting=" + func_CronetUrlRequest_setOnDestroyedUploadCallbackForTesting)
    if (func_CronetUrlRequest_setOnDestroyedUploadCallbackForTesting) {
      func_CronetUrlRequest_setOnDestroyedUploadCallbackForTesting.implementation = function (onDestroyedUploadCallbackForTesting) {
        var funcName = "CronetUrlRequest.setOnDestroyedUploadCallbackForTesting"
        var funcParaDict = {
          "onDestroyedUploadCallbackForTesting": onDestroyedUploadCallbackForTesting,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setOnDestroyedUploadCallbackForTesting(onDestroyedUploadCallbackForTesting)
      }
    }

    // public long getUrlRequestAdapterForTesting() {
    // 
    var func_CronetUrlRequest_getUrlRequestAdapterForTesting = cls_CronetUrlRequest.getUrlRequestAdapterForTesting
    console.log("func_CronetUrlRequest_getUrlRequestAdapterForTesting=" + func_CronetUrlRequest_getUrlRequestAdapterForTesting)
    if (func_CronetUrlRequest_getUrlRequestAdapterForTesting) {
      func_CronetUrlRequest_getUrlRequestAdapterForTesting.implementation = function () {
        var funcName = "CronetUrlRequest.getUrlRequestAdapterForTesting"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retUrlRequestAdapterForTesting = this.getUrlRequestAdapterForTesting()
        console.log(funcName + " => retUrlRequestAdapterForTesting=" + retUrlRequestAdapterForTesting)
        return retUrlRequestAdapterForTesting
      }
    }

    // private void postTaskToExecutor(Runnable task, String name) {
    // 
    var func_CronetUrlRequest_postTaskToExecutor = cls_CronetUrlRequest.postTaskToExecutor
    console.log("func_CronetUrlRequest_postTaskToExecutor=" + func_CronetUrlRequest_postTaskToExecutor)
    if (func_CronetUrlRequest_postTaskToExecutor) {
      func_CronetUrlRequest_postTaskToExecutor.implementation = function (task, name) {
        var funcName = "CronetUrlRequest.postTaskToExecutor"
        var funcParaDict = {
          "task": task,
          "name": name,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.postTaskToExecutor(task, name)
      }
    }

    // private static int convertRequestPriority(int priority) {
    // 
    var func_CronetUrlRequest_convertRequestPriority = cls_CronetUrlRequest.convertRequestPriority
    console.log("func_CronetUrlRequest_convertRequestPriority=" + func_CronetUrlRequest_convertRequestPriority)
    if (func_CronetUrlRequest_convertRequestPriority) {
      func_CronetUrlRequest_convertRequestPriority.implementation = function (priority) {
        var funcName = "CronetUrlRequest.convertRequestPriority"
        var funcParaDict = {
          "priority": priority,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInt = this.convertRequestPriority(priority)
        console.log(funcName + " => retInt=" + retInt)
        return retInt
      }
    }

    // private static int convertIdempotency(int idempotency) {
    // 
    var func_CronetUrlRequest_convertIdempotency = cls_CronetUrlRequest.convertIdempotency
    console.log("func_CronetUrlRequest_convertIdempotency=" + func_CronetUrlRequest_convertIdempotency)
    if (func_CronetUrlRequest_convertIdempotency) {
      func_CronetUrlRequest_convertIdempotency.implementation = function (idempotency) {
        var funcName = "CronetUrlRequest.convertIdempotency"
        var funcParaDict = {
          "idempotency": idempotency,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInt = this.convertIdempotency(idempotency)
        console.log(funcName + " => retInt=" + retInt)
        return retInt
      }
    }

    /* private UrlResponseInfoImpl prepareResponseInfoOnNetworkThread(
            int httpStatusCode,
            String httpStatusText,
            String[] headers,
            boolean wasCached,
            String negotiatedProtocol,
            String proxyServer,
            long receivedByteCount) {
    */
    // 
    var func_CronetUrlRequest_prepareResponseInfoOnNetworkThread = cls_CronetUrlRequest.prepareResponseInfoOnNetworkThread
    console.log("func_CronetUrlRequest_prepareResponseInfoOnNetworkThread=" + func_CronetUrlRequest_prepareResponseInfoOnNetworkThread)
    if (func_CronetUrlRequest_prepareResponseInfoOnNetworkThread) {
      func_CronetUrlRequest_prepareResponseInfoOnNetworkThread.implementation = function (httpStatusCode, httpStatusText, headers, wasCached, negotiatedProtocol, proxyServer, receivedByteCount) {
        var funcName = "CronetUrlRequest.prepareResponseInfoOnNetworkThread"
        var funcParaDict = {
          "httpStatusCode": httpStatusCode,
          "httpStatusText": httpStatusText,
          "headers": headers,
          "wasCached": wasCached,
          "negotiatedProtocol": negotiatedProtocol,
          "proxyServer": proxyServer,
          "receivedByteCount": receivedByteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retUrlResponseInfoImpl = this.prepareResponseInfoOnNetworkThread(httpStatusCode, httpStatusText, headers, wasCached, negotiatedProtocol, proxyServer, receivedByteCount)
        console.log(funcName + " => retUrlResponseInfoImpl=" + retUrlResponseInfoImpl)
        return retUrlResponseInfoImpl
      }
    }

    // private void checkNotStarted() {
    // 
    var func_CronetUrlRequest_checkNotStarted = cls_CronetUrlRequest.checkNotStarted
    console.log("func_CronetUrlRequest_checkNotStarted=" + func_CronetUrlRequest_checkNotStarted)
    if (func_CronetUrlRequest_checkNotStarted) {
      func_CronetUrlRequest_checkNotStarted.implementation = function () {
        var funcName = "CronetUrlRequest.checkNotStarted"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.checkNotStarted()
      }
    }

    /* private void destroyRequestAdapterLocked(
            @RequestFinishedInfoImpl.FinishedReason int finishedReason) {
    */
    // 
    var func_CronetUrlRequest_destroyRequestAdapterLocked = cls_CronetUrlRequest.destroyRequestAdapterLocked
    console.log("func_CronetUrlRequest_destroyRequestAdapterLocked=" + func_CronetUrlRequest_destroyRequestAdapterLocked)
    if (func_CronetUrlRequest_destroyRequestAdapterLocked) {
      func_CronetUrlRequest_destroyRequestAdapterLocked.implementation = function (finishedReason) {
        var funcName = "CronetUrlRequest.destroyRequestAdapterLocked"
        var funcParaDict = {
          "finishedReason": finishedReason,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.destroyRequestAdapterLocked(finishedReason)
      }
    }

    // private void onNonfinalCallbackException(Exception e) {
    // 
    var func_CronetUrlRequest_onNonfinalCallbackException = cls_CronetUrlRequest.onNonfinalCallbackException
    console.log("func_CronetUrlRequest_onNonfinalCallbackException=" + func_CronetUrlRequest_onNonfinalCallbackException)
    if (func_CronetUrlRequest_onNonfinalCallbackException) {
      func_CronetUrlRequest_onNonfinalCallbackException.implementation = function (e) {
        var funcName = "CronetUrlRequest.onNonfinalCallbackException"
        var funcParaDict = {
          "e": e,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onNonfinalCallbackException(e)
      }
    }

    // private void onFinalCallbackException(String method, Exception e) {
    // 
    var func_CronetUrlRequest_onFinalCallbackException = cls_CronetUrlRequest.onFinalCallbackException
    console.log("func_CronetUrlRequest_onFinalCallbackException=" + func_CronetUrlRequest_onFinalCallbackException)
    if (func_CronetUrlRequest_onFinalCallbackException) {
      func_CronetUrlRequest_onFinalCallbackException.implementation = function (method, e) {
        var funcName = "CronetUrlRequest.onFinalCallbackException"
        var funcParaDict = {
          "method": method,
          "e": e,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onFinalCallbackException(method, e)
      }
    }

    // void onUploadException(Throwable e) {
    // 
    var func_CronetUrlRequest_onUploadException = cls_CronetUrlRequest.onUploadException
    console.log("func_CronetUrlRequest_onUploadException=" + func_CronetUrlRequest_onUploadException)
    if (func_CronetUrlRequest_onUploadException) {
      func_CronetUrlRequest_onUploadException.implementation = function (e) {
        var funcName = "CronetUrlRequest.onUploadException"
        var funcParaDict = {
          "e": e,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onUploadException(e)
      }
    }

    // private void failWithException(final CronetException exception) {
    // 
    var func_CronetUrlRequest_failWithException = cls_CronetUrlRequest.failWithException
    console.log("func_CronetUrlRequest_failWithException=" + func_CronetUrlRequest_failWithException)
    if (func_CronetUrlRequest_failWithException) {
      func_CronetUrlRequest_failWithException.implementation = function (exception) {
        var funcName = "CronetUrlRequest.failWithException"
        var funcParaDict = {
          "exception": exception,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.failWithException(exception)
      }
    }

    /* private void onRedirectReceived(
            final String newLocation,
            int httpStatusCode,
            String httpStatusText,
            String[] headers,
            boolean wasCached,
            String negotiatedProtocol,
            String proxyServer,
            long receivedByteCount) {
    */
    // 
    var func_CronetUrlRequest_onRedirectReceived = cls_CronetUrlRequest.onRedirectReceived
    console.log("func_CronetUrlRequest_onRedirectReceived=" + func_CronetUrlRequest_onRedirectReceived)
    if (func_CronetUrlRequest_onRedirectReceived) {
      func_CronetUrlRequest_onRedirectReceived.implementation = function (newLocation, httpStatusCode, httpStatusText, headers, wasCached, negotiatedProtocol, proxyServer, receivedByteCount) {
        var funcName = "CronetUrlRequest.onRedirectReceived"
        var funcParaDict = {
          "newLocation": newLocation,
          "httpStatusCode": httpStatusCode,
          "httpStatusText": httpStatusText,
          "headers": headers,
          "wasCached": wasCached,
          "negotiatedProtocol": negotiatedProtocol,
          "proxyServer": proxyServer,
          "receivedByteCount": receivedByteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onRedirectReceived(newLocation, httpStatusCode, httpStatusText, headers, wasCached, negotiatedProtocol, proxyServer, receivedByteCount)
      }
    }

    /* private void onResponseStarted(
            int httpStatusCode,
            String httpStatusText,
            String[] headers,
            boolean wasCached,
            String negotiatedProtocol,
            String proxyServer,
            long receivedByteCount) {
    */
    // 
    var func_CronetUrlRequest_onResponseStarted = cls_CronetUrlRequest.onResponseStarted
    console.log("func_CronetUrlRequest_onResponseStarted=" + func_CronetUrlRequest_onResponseStarted)
    if (func_CronetUrlRequest_onResponseStarted) {
      func_CronetUrlRequest_onResponseStarted.implementation = function (httpStatusCode, httpStatusText, headers, wasCached, negotiatedProtocol, proxyServer, receivedByteCount) {
        var funcName = "CronetUrlRequest.onResponseStarted"
        var funcParaDict = {
          "httpStatusCode": httpStatusCode,
          "httpStatusText": httpStatusText,
          "headers": headers,
          "wasCached": wasCached,
          "negotiatedProtocol": negotiatedProtocol,
          "proxyServer": proxyServer,
          "receivedByteCount": receivedByteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onResponseStarted(httpStatusCode, httpStatusText, headers, wasCached, negotiatedProtocol, proxyServer, receivedByteCount)
      }
    }

    /* private void onReadCompleted(
            final ByteBuffer byteBuffer,
            int bytesRead,
            int initialPosition,
            int initialLimit,
            long receivedByteCount) {
    */
    // 
    var func_CronetUrlRequest_onReadCompleted = cls_CronetUrlRequest.onReadCompleted
    console.log("func_CronetUrlRequest_onReadCompleted=" + func_CronetUrlRequest_onReadCompleted)
    if (func_CronetUrlRequest_onReadCompleted) {
      func_CronetUrlRequest_onReadCompleted.implementation = function (byteBuffer, bytesRead, initialPosition, initialLimit, receivedByteCount) {
        var funcName = "CronetUrlRequest.onReadCompleted"
        var funcParaDict = {
          "byteBuffer": byteBuffer,
          "bytesRead": bytesRead,
          "initialPosition": initialPosition,
          "initialLimit": initialLimit,
          "receivedByteCount": receivedByteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onReadCompleted(byteBuffer, bytesRead, initialPosition, initialLimit, receivedByteCount)
      }
    }

    // private void onSucceeded(long receivedByteCount) {
    // 
    var func_CronetUrlRequest_onSucceeded = cls_CronetUrlRequest.onSucceeded
    console.log("func_CronetUrlRequest_onSucceeded=" + func_CronetUrlRequest_onSucceeded)
    if (func_CronetUrlRequest_onSucceeded) {
      func_CronetUrlRequest_onSucceeded.implementation = function (receivedByteCount) {
        var funcName = "CronetUrlRequest.onSucceeded"
        var funcParaDict = {
          "receivedByteCount": receivedByteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onSucceeded(receivedByteCount)
      }
    }

    /* private void onError(
            int errorCode,
            int nativeError,
            int nativeQuicError,
            @ConnectionCloseSource int source,
            String errorString,
            long receivedByteCount) {
    */
    // 
    var func_CronetUrlRequest_onError = cls_CronetUrlRequest.onError
    console.log("func_CronetUrlRequest_onError=" + func_CronetUrlRequest_onError)
    if (func_CronetUrlRequest_onError) {
      func_CronetUrlRequest_onError.implementation = function (errorCode, nativeError, nativeQuicError, source, errorString, receivedByteCount) {
        var funcName = "CronetUrlRequest.onError"
        var funcParaDict = {
          "errorCode": errorCode,
          "nativeError": nativeError,
          "nativeQuicError": nativeQuicError,
          "source": source,
          "errorString": errorString,
          "receivedByteCount": receivedByteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onError(errorCode, nativeError, nativeQuicError, source, errorString, receivedByteCount)
      }
    }

    // private void onCanceled() {
    // 
    var func_CronetUrlRequest_onCanceled = cls_CronetUrlRequest.onCanceled
    console.log("func_CronetUrlRequest_onCanceled=" + func_CronetUrlRequest_onCanceled)
    if (func_CronetUrlRequest_onCanceled) {
      func_CronetUrlRequest_onCanceled.implementation = function () {
        var funcName = "CronetUrlRequest.onCanceled"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onCanceled()
      }
    }

    /* private void onStatus(
            final VersionSafeCallbacks.UrlRequestStatusListener listener, final int loadState) {
    */
    // 
    var func_CronetUrlRequest_onStatus = cls_CronetUrlRequest.onStatus
    console.log("func_CronetUrlRequest_onStatus=" + func_CronetUrlRequest_onStatus)
    if (func_CronetUrlRequest_onStatus) {
      func_CronetUrlRequest_onStatus.implementation = function (listener, loadState) {
        var funcName = "CronetUrlRequest.onStatus"
        var funcParaDict = {
          "listener": listener,
          "loadState": loadState,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onStatus(listener, loadState)
      }
    }

    /* private void onMetricsCollected(
            long requestStartMs,
            long dnsStartMs,
            long dnsEndMs,
            long connectStartMs,
            long connectEndMs,
            long sslStartMs,
            long sslEndMs,
            long sendingStartMs,
            long sendingEndMs,
            long pushStartMs,
            long pushEndMs,
            long responseStartMs,
            long requestEndMs,
            boolean socketReused,
            long sentByteCount,
            long receivedByteCount,
            boolean quicConnectionMigrationAttempted,
            boolean quicConnectionMigrationSuccessful) {
    */
    // 
    var func_CronetUrlRequest_onMetricsCollected = cls_CronetUrlRequest.onMetricsCollected
    console.log("func_CronetUrlRequest_onMetricsCollected=" + func_CronetUrlRequest_onMetricsCollected)
    if (func_CronetUrlRequest_onMetricsCollected) {
      func_CronetUrlRequest_onMetricsCollected.implementation = function (requestStartMs, dnsStartMs, dnsEndMs, connectStartMs, connectEndMs, sslStartMs, sslEndMs, sendingStartMs, sendingEndMs, pushStartMs, pushEndMs, responseStartMs, requestEndMs, socketReused, sentByteCount, receivedByteCount, quicConnectionMigrationAttempted, quicConnectionMigrationSuccessful) {
        var funcName = "CronetUrlRequest.onMetricsCollected"
        var funcParaDict = {
          "requestStartMs": requestStartMs,
          "dnsStartMs": dnsStartMs,
          "dnsEndMs": dnsEndMs,
          "connectStartMs": connectStartMs,
          "connectEndMs": connectEndMs,
          "sslStartMs": sslStartMs,
          "sslEndMs": sslEndMs,
          "sendingStartMs": sendingStartMs,
          "sendingEndMs": sendingEndMs,
          "pushStartMs": pushStartMs,
          "pushEndMs": pushEndMs,
          "responseStartMs": responseStartMs,
          "requestEndMs": requestEndMs,
          "socketReused": socketReused,
          "sentByteCount": sentByteCount,
          "receivedByteCount": receivedByteCount,
          "quicConnectionMigrationAttempted": quicConnectionMigrationAttempted,
          "quicConnectionMigrationSuccessful": quicConnectionMigrationSuccessful,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onMetricsCollected(requestStartMs, dnsStartMs, dnsEndMs, connectStartMs, connectEndMs, sslStartMs, sslEndMs, sendingStartMs, sendingEndMs, pushStartMs, pushEndMs, responseStartMs, requestEndMs, socketReused, sentByteCount, receivedByteCount, quicConnectionMigrationAttempted, quicConnectionMigrationSuccessful)
      }
    }

    // private void onNativeAdapterDestroyed() {
    // 
    var func_CronetUrlRequest_onNativeAdapterDestroyed = cls_CronetUrlRequest.onNativeAdapterDestroyed
    console.log("func_CronetUrlRequest_onNativeAdapterDestroyed=" + func_CronetUrlRequest_onNativeAdapterDestroyed)
    if (func_CronetUrlRequest_onNativeAdapterDestroyed) {
      func_CronetUrlRequest_onNativeAdapterDestroyed.implementation = function () {
        var funcName = "CronetUrlRequest.onNativeAdapterDestroyed"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onNativeAdapterDestroyed()
      }
    }

    // void checkCallingThread() {
    // 
    var func_CronetUrlRequest_checkCallingThread = cls_CronetUrlRequest.checkCallingThread
    console.log("func_CronetUrlRequest_checkCallingThread=" + func_CronetUrlRequest_checkCallingThread)
    if (func_CronetUrlRequest_checkCallingThread) {
      func_CronetUrlRequest_checkCallingThread.implementation = function () {
        var funcName = "CronetUrlRequest.checkCallingThread"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.checkCallingThread()
      }
    }

    // private int mapUrlRequestErrorToApiErrorCode(int errorCode) {
    // 
    var func_CronetUrlRequest_mapUrlRequestErrorToApiErrorCode = cls_CronetUrlRequest.mapUrlRequestErrorToApiErrorCode
    console.log("func_CronetUrlRequest_mapUrlRequestErrorToApiErrorCode=" + func_CronetUrlRequest_mapUrlRequestErrorToApiErrorCode)
    if (func_CronetUrlRequest_mapUrlRequestErrorToApiErrorCode) {
      func_CronetUrlRequest_mapUrlRequestErrorToApiErrorCode.implementation = function (errorCode) {
        var funcName = "CronetUrlRequest.mapUrlRequestErrorToApiErrorCode"
        var funcParaDict = {
          "errorCode": errorCode,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInt = this.mapUrlRequestErrorToApiErrorCode(errorCode)
        console.log(funcName + " => retInt=" + retInt)
        return retInt
      }
    }

    // private CronetTrafficInfo buildCronetTrafficInfo() {
    // 
    var func_CronetUrlRequest_buildCronetTrafficInfo = cls_CronetUrlRequest.buildCronetTrafficInfo
    console.log("func_CronetUrlRequest_buildCronetTrafficInfo=" + func_CronetUrlRequest_buildCronetTrafficInfo)
    if (func_CronetUrlRequest_buildCronetTrafficInfo) {
      func_CronetUrlRequest_buildCronetTrafficInfo.implementation = function () {
        var funcName = "CronetUrlRequest.buildCronetTrafficInfo"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retCronetTrafficInfo = this.buildCronetTrafficInfo()
        console.log(funcName + " => retCronetTrafficInfo=" + retCronetTrafficInfo)
        return retCronetTrafficInfo
      }
    }

    // private void maybeReportMetrics() {
    // 
    var func_CronetUrlRequest_maybeReportMetrics = cls_CronetUrlRequest.maybeReportMetrics
    console.log("func_CronetUrlRequest_maybeReportMetrics=" + func_CronetUrlRequest_maybeReportMetrics)
    if (func_CronetUrlRequest_maybeReportMetrics) {
      func_CronetUrlRequest_maybeReportMetrics.implementation = function () {
        var funcName = "CronetUrlRequest.maybeReportMetrics"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.maybeReportMetrics()
      }
    }

  }

  static CronetUrlRequest() {
    var clsName_CronetUrlRequest = "org.chromium.net.impl.CronetUrlRequest"
    FridaAndroidUtil.updateClassLoader(clsName_CronetUrlRequest)
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_CronetUrlRequest)

    var cls_CronetUrlRequest = Java.use(clsName_CronetUrlRequest)
    console.log("cls_CronetUrlRequest=" + cls_CronetUrlRequest)

    FridaHookAndroidJava.CronetUrlRequest_origCode(cls_CronetUrlRequest)
  }

  static UUID(callback_isShowLog=null) {
    var clsName_UUID = "java.util.UUID"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_UUID)

    var cls_UUID = Java.use(clsName_UUID)
    console.log("cls_UUID=" + cls_UUID)

    var curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    // var curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // UUID([B)
    // public java.util.UUID java.util.UUID.<init>(byte[])
    var func_UUID_ctor_1b = cls_UUID.$init.overload('[B')
    console.log("func_UUID_ctor_1b=" + func_UUID_ctor_1b)
    if (func_UUID_ctor_1b) {
      func_UUID_ctor_1b.implementation = function (byteArray) {
        var funcName = "UUID([B)"
        var funcParaDict = {
          "byteArray": byteArray,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        this.$init(byteArray)
        var newUUID_1b = this
        if (isShowLog){
          console.log(funcName + " => newUUID_1b=" + newUUID_1b)
        }
        return
      }
    }

    // UUID(long mostSigBits, long leastSigBits)
    // public java.util.UUID java.util.UUID.<init>(long, long)
    var func_UUID_ctor_2pll = cls_UUID.$init.overload('long', 'long')
    console.log("func_UUID_ctor_2pll=" + func_UUID_ctor_2pll)
    if (func_UUID_ctor_2pll) {
      func_UUID_ctor_2pll.implementation = function (mostSigBits, leastSigBits) {
        var funcName = "UUID(long,long)"
        var funcParaDict = {
          "mostSigBits": mostSigBits,
          "leastSigBits": leastSigBits,
        }

        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        this.$init(mostSigBits, leastSigBits)
        var newUUID_2pll = this
        if (isShowLog){
          console.log(funcName + " => newUUID_2pll=" + newUUID_2pll)
        }
        return
      }
    }

    // static UUID randomUUID()
    // public static java.util.UUID java.util.UUID.randomUUID()
    var func_UUID_randomUUID = cls_UUID.randomUUID
    console.log("func_UUID_randomUUID=" + func_UUID_randomUUID)
    if (func_UUID_randomUUID) {
      func_UUID_randomUUID.implementation = function () {
        var funcName = "UUID.randomUUID"
        var funcParaDict = {}

        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retUUID = this.randomUUID()
        if (isShowLog){
          console.log(funcName + " => retUUID=" + retUUID)
        }
        return retUUID
      }
    }

    // long getLeastSignificantBits()
    // public long java.util.UUID.getLeastSignificantBits()
    var func_UUID_getLeastSignificantBits = cls_UUID.getLeastSignificantBits
    console.log("func_UUID_getLeastSignificantBits=" + func_UUID_getLeastSignificantBits)
    if (func_UUID_getLeastSignificantBits) {
      func_UUID_getLeastSignificantBits.implementation = function () {
        var funcName = "UUID.getLeastSignificantBits"
        var funcParaDict = {}

        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retLeastSignificantBits = this.getLeastSignificantBits()
        if (isShowLog){
          console.log(funcName + " => retLeastSignificantBits=" + retLeastSignificantBits)
        }
        return retLeastSignificantBits
      }
    }

    // long getMostSignificantBits()
    // public long java.util.UUID.getMostSignificantBits()
    var func_UUID_getMostSignificantBits = cls_UUID.getMostSignificantBits
    console.log("func_UUID_getMostSignificantBits=" + func_UUID_getMostSignificantBits)
    if (func_UUID_getMostSignificantBits) {
      func_UUID_getMostSignificantBits.implementation = function () {
        var funcName = "UUID.getMostSignificantBits"
        var funcParaDict = {}

        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retMostSignificantBits = this.getMostSignificantBits()
        if (isShowLog){
          console.log(funcName + " => retMostSignificantBits=" + retMostSignificantBits)
        }
        return retMostSignificantBits
      }
    }

  }

  static Context() {
    var clsName_Context = "android.content.Context"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Context)

    var cls_Context = Java.use(clsName_Context)
    console.log("cls_Context=" + cls_Context)

    // public abstract Context createPackageContext (String packageName, int flags)
    // 
    var func_Context_createPackageContext = cls_Context.createPackageContext
    console.log("func_Context_createPackageContext=" + func_Context_createPackageContext)
    if (func_Context_createPackageContext) {
      func_Context_createPackageContext.implementation = function (packageName, flags) {
        var funcName = "Context.createPackageContext"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retContext = this.createPackageContext(packageName, flags)
        console.log(funcName + " => retContext=" + retContext)
        return retContext
      }
    }

    // public abstract FileInputStream openFileInput(String name)
    // 
    var func_Context_openFileInput = cls_Context.openFileInput
    console.log("func_Context_openFileInput=" + func_Context_openFileInput)
    if (func_Context_openFileInput) {
      func_Context_openFileInput.implementation = function (name) {
        var funcName = "Context.openFileInput"
        var funcParaDict = {
          "name": name,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retFileInputStream = this.openFileInput(name)
        console.log(funcName + " => retFileInputStream=" + retFileInputStream)
        return retFileInputStream
      }
    }

    // public abstract File getDir(String name, int mode)
    // 
    var func_Context_getDir = cls_Context.getDir
    console.log("func_Context_getDir=" + func_Context_getDir)
    if (func_Context_getDir) {
      func_Context_getDir.implementation = function (name, mode) {
        var funcName = "Context.getDir"
        var funcParaDict = {
          "name": name,
          "mode": mode,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retDir = this.getDir(name, mode)
        console.log(funcName + " => retDir=" + retDir)
        return retDir
      }
    }

    // public abstract SharedPreferences getSharedPreferences(String name, int mode)
    // public abstract android.content.SharedPreferences android.content.Context.getSharedPreferences(java.lang.String,int)
    var func_Context_getSharedPreferences_2psi = cls_Context.getSharedPreferences.overload('java.lang.String', 'int')
    console.log("func_Context_getSharedPreferences_2psi=" + func_Context_getSharedPreferences_2psi)
    if (func_Context_getSharedPreferences_2psi) {
      func_Context_getSharedPreferences_2psi.implementation = function (name, mode) {
        var funcName = "Context.getSharedPreferences_2psi"
        var funcParaDict = {
          "name": name,
          "mode": mode,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retSharedPreferences_2psi = this.getSharedPreferences(name, mode)
        console.log(funcName + " => retSharedPreferences_2psi=" + retSharedPreferences_2psi)
        return retSharedPreferences_2psi
      }
    }

  }

  static ContextWrapper() {
    var clsName_ContextWrapper = "android.content.ContextWrapper"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_ContextWrapper)

    var cls_ContextWrapper = Java.use(clsName_ContextWrapper)
    console.log("cls_ContextWrapper=" + cls_ContextWrapper)

    // public PackageManager getPackageManager()
    // public android.content.pm.PackageManager android.content.ContextWrapper.getPackageManager()
    var func_ContextWrapper_getPackageManager = cls_ContextWrapper.getPackageManager
    console.log("func_ContextWrapper_getPackageManager=" + func_ContextWrapper_getPackageManager)
    if (func_ContextWrapper_getPackageManager) {
      func_ContextWrapper_getPackageManager.implementation = function () {
        var funcName = "ContextWrapper.getPackageManager"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retPackageManager = this.getPackageManager()
        console.log(funcName + " => retPackageManager=" + retPackageManager)
        return retPackageManager
      }
    }

    // public Object getSystemService(String name)
    // public java.lang.Object android.content.ContextWrapper.getSystemService(java.lang.String)
    var func_ContextWrapper_getSystemService = cls_ContextWrapper.getSystemService
    console.log("func_ContextWrapper_getSystemService=" + func_ContextWrapper_getSystemService)
    if (func_ContextWrapper_getSystemService) {
      func_ContextWrapper_getSystemService.implementation = function (name) {
        var funcName = "ContextWrapper.getSystemService"
        var funcParaDict = {
          "name": name,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retSystemService = this.getSystemService(name)
        console.log(funcName + " => retSystemService=" + retSystemService)
        return retSystemService
      }
    }


    // public ContentResolver getContentResolver()
    // public android.content.ContentResolver android.content.ContextWrapper.getContentResolver()
    var func_ContextWrapper_getContentResolver = cls_ContextWrapper.getContentResolver
    console.log("func_ContextWrapper_getContentResolver=" + func_ContextWrapper_getContentResolver)
    if (func_ContextWrapper_getContentResolver) {
      func_ContextWrapper_getContentResolver.implementation = function () {
        var funcName = "ContextWrapper.getContentResolver"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retContentResolver = this.getContentResolver()
        console.log(funcName + " => retContentResolver=" + retContentResolver)
        return retContentResolver
      }
    }

    // SharedPreferences getSharedPreferences(String name, int mode)
    // public android.content.SharedPreferences android.content.ContextWrapper.getSharedPreferences(java.lang.String,int)
    var func_ContextWrapper_getSharedPreferences = cls_ContextWrapper.getSharedPreferences.overload('java.lang.String', 'int')
    console.log("func_ContextWrapper_getSharedPreferences=" + func_ContextWrapper_getSharedPreferences)
    if (func_ContextWrapper_getSharedPreferences) {
      func_ContextWrapper_getSharedPreferences.implementation = function (name, mode) {
        var funcName = "ContextWrapper.getSharedPreferences"
        var funcParaDict = {
          "name": name,
          "mode": mode,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retSharedPreferences = this.getSharedPreferences(name, mode)
        // console.log(funcName + " => retSharedPreferences=" + retSharedPreferences)
        console.log(`${funcName}(name=${name},mode=${mode}) => retSharedPreferences=${retSharedPreferences}`)

        // // for debug: emulate can NOT get checkin related SharedPreferences
        // if (
        //   (name == "Checkin") ||
        //   (name == "constellation_prefs") ||
        //   (name == "CheckinService")
        //  ) {
        //   retSharedPreferences = null
        //   var dbgStr = "for debug: emulate can NOT get checkin related SharedPreferences"
        //   console.log(dbgStr + " " + funcName + " => retSharedPreferences=" + retSharedPreferences)
        // }

        return retSharedPreferences
      }
    }

    // Context createPackageContext(String packageName, int flags)
    // public android.content.Context android.content.ContextWrapper.createPackageContext(java.lang.String,int) throws android.content.pm.PackageManager$NameNotFoundException
    var func_ContextWrapper_createPackageContext = cls_ContextWrapper.createPackageContext
    console.log("func_ContextWrapper_createPackageContext=" + func_ContextWrapper_createPackageContext)
    if (func_ContextWrapper_createPackageContext) {
      func_ContextWrapper_createPackageContext.implementation = function (packageName, flags) {
        var funcName = "ContextWrapper.createPackageContext"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retContext = this.createPackageContext(packageName, flags)
        // console.log(funcName + " => retContext=" + retContext)
        console.log(`${funcName}(packageName=${packageName},flags=${flags}) => retContext=${retContext}`)
        return retContext
      }
    }

    // FileInputStream openFileInput(String name)
    // public java.io.FileInputStream android.content.ContextWrapper.openFileInput(java.lang.String) throws java.io.FileNotFoundException
    var func_ContextWrapper_openFileInput = cls_ContextWrapper.openFileInput
    console.log("func_ContextWrapper_openFileInput=" + func_ContextWrapper_openFileInput)
    if (func_ContextWrapper_openFileInput) {
      func_ContextWrapper_openFileInput.implementation = function (name) {
        var funcName = "ContextWrapper.openFileInput"
        var funcParaDict = {
          "name": name,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retFileInputStream = this.openFileInput(name)

        // // for debug: emulate can NOT get checkin_id_token
        // if (
        //   name == "checkin_id_token" // /data/user/0/com.google.android.gms/files/checkin_id_token
        //   || name == "security_token" // /data/user/0/com.google.android.gsf/files/security_token
        // ) {
        //   // retFileInputStream = null
        //   // var dbgStr = "for debug: emulate can NOT get checkin_id_token"
        //   // console.log(dbgStr + " " + funcName + " => retFileInputStream=" + retFileInputStream)

        //   // var notFoundException = new FridaAndroidUtil.FileNotFoundException("Emulated file not exist: " + name)
        //   var notFoundException = FridaAndroidUtil.FileNotFoundException.$new("Emulated file not exist: " + name)
        //   console.log(`${funcName}(name=${name}) => notFoundException=${notFoundException}`)
        //   throw notFoundException
        // } else {
          // console.log(funcName + " => retFileInputStream=" + retFileInputStream)
          console.log(`${funcName}(name=${name}) => retFileInputStream=${retFileInputStream}`)
          return retFileInputStream
        // }

      }
    }

    // // public Resources getResources()
    // // public android.content.res.Resources android.content.ContextWrapper.getResources()
    // var func_ContextWrapper_getResources = cls_ContextWrapper.getResources
    // console.log("func_ContextWrapper_getResources=" + func_ContextWrapper_getResources)
    // if (func_ContextWrapper_getResources) {
    //   func_ContextWrapper_getResources.implementation = function () {
    //     var funcName = "ContextWrapper.getResources"
    //     var funcParaDict = {}
    //     FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
    //     var retResources = this.getResources()
    //     console.log(funcName + " => retResources=" + retResources)
    //     return retResources
    //   }
    // }

    // public AssetManager getAssets()
    // public android.content.res.AssetManager android.content.ContextWrapper.getAssets()
    var func_ContextWrapper_getAssets = cls_ContextWrapper.getAssets
    console.log("func_ContextWrapper_getAssets=" + func_ContextWrapper_getAssets)
    if (func_ContextWrapper_getAssets) {
      func_ContextWrapper_getAssets.implementation = function () {
        var funcName = "ContextWrapper.getAssets"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retAssetManager = this.getAssets()
        console.log(funcName + " => retAssetManager=" + retAssetManager)
        return retAssetManager
      }
    }

    // SharedPreferences getSharedPreferences(String name, int mode)
    // public android.content.SharedPreferences android.content.ContextWrapper.getSharedPreferences(java.lang.String,int)
    var func_ContextWrapper_getSharedPreferences_2pnm = cls_ContextWrapper.getSharedPreferences.overload("java.lang.String", "int")
    console.log("func_ContextWrapper_getSharedPreferences_2pnm=" + func_ContextWrapper_getSharedPreferences_2pnm)
    if (func_ContextWrapper_getSharedPreferences_2pnm) {
      func_ContextWrapper_getSharedPreferences_2pnm.implementation = function (name, mode) {
        var funcName = "ContextWrapper.getSharedPreferences(name,mode)"
        var funcParaDict = {
          "name": name,
          "mode": mode
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retSharedPreferences_2pnm = this.getSharedPreferences(name, mode)
        var clsNameValStr = FridaAndroidUtil.valueToNameStr(retSharedPreferences_2pnm)
        console.log(funcName + " => retSharedPreferences_2pnm=" + clsNameValStr)
          return retSharedPreferences_2pnm
      }
    }

  }

  static SharedPreferencesImpl_EditorImpl(){
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_SharedPreferencesImpl_EditorImpl)

    var cls_SharedPreferencesImpl_EditorImpl = Java.use(FridaAndroidUtil.clsName_SharedPreferencesImpl_EditorImpl)
    console.log("cls_SharedPreferencesImpl_EditorImpl=" + cls_SharedPreferencesImpl_EditorImpl)

    const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    // const curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // public Editor putString(String key, @Nullable String value) {
    // public android.content.SharedPreferences$Editor android.app.SharedPreferencesImpl$EditorImpl.putString(java.lang.String,java.lang.String)
    var func_SharedPreferencesImpl_EditorImpl_putString = cls_SharedPreferencesImpl_EditorImpl.putString
    console.log("func_SharedPreferencesImpl_EditorImpl_putString=" + func_SharedPreferencesImpl_EditorImpl_putString)
    if (func_SharedPreferencesImpl_EditorImpl_putString) {
      func_SharedPreferencesImpl_EditorImpl_putString.implementation = function (key, value) {
        var funcName = "SharedPreferencesImpl.EditorImpl.putString"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.putString(key, value)
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }

    // public Editor putStringSet(String key, @Nullable Set<String> values) {
    // public android.content.SharedPreferences$Editor android.app.SharedPreferencesImpl$EditorImpl.putStringSet(java.lang.String,java.util.Set)
    var func_SharedPreferencesImpl_EditorImpl_putStringSet = cls_SharedPreferencesImpl_EditorImpl.putStringSet
    console.log("func_SharedPreferencesImpl_EditorImpl_putStringSet=" + func_SharedPreferencesImpl_EditorImpl_putStringSet)
    if (func_SharedPreferencesImpl_EditorImpl_putStringSet) {
      func_SharedPreferencesImpl_EditorImpl_putStringSet.implementation = function (key, values) {
        var funcName = "SharedPreferencesImpl.EditorImpl.putStringSet"
        var funcParaDict = {
          "key": key,
          "values": values,
        }
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.putStringSet(key, values)
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }

    // public Editor remove(String key) {
    // public android.content.SharedPreferences$Editor android.app.SharedPreferencesImpl$EditorImpl.remove(java.lang.String)
    var func_SharedPreferencesImpl_EditorImpl_remove = cls_SharedPreferencesImpl_EditorImpl.remove
    console.log("func_SharedPreferencesImpl_EditorImpl_remove=" + func_SharedPreferencesImpl_EditorImpl_remove)
    if (func_SharedPreferencesImpl_EditorImpl_remove) {
      func_SharedPreferencesImpl_EditorImpl_remove.implementation = function (key) {
        var funcName = "SharedPreferencesImpl.EditorImpl.remove"
        var funcParaDict = {
          "key": key,
        }
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.remove(key)
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }

    // public Editor putLong(String key, long value) {
    // public android.content.SharedPreferences$Editor android.app.SharedPreferencesImpl$EditorImpl.putLong(java.lang.String,long)
    var func_SharedPreferencesImpl_EditorImpl_putLong = cls_SharedPreferencesImpl_EditorImpl.putLong
    console.log("func_SharedPreferencesImpl_EditorImpl_putLong=" + func_SharedPreferencesImpl_EditorImpl_putLong)
    if (func_SharedPreferencesImpl_EditorImpl_putLong) {
      func_SharedPreferencesImpl_EditorImpl_putLong.implementation = function (key, value) {
        var funcName = "SharedPreferencesImpl.EditorImpl.putLong"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.putLong(key, value)
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }

    // public Editor putBoolean(String key, boolean value) {
    // public android.content.SharedPreferences$Editor android.app.SharedPreferencesImpl$EditorImpl.putBoolean(java.lang.String,boolean)
    var func_SharedPreferencesImpl_EditorImpl_putBoolean = cls_SharedPreferencesImpl_EditorImpl.putBoolean
    console.log("func_SharedPreferencesImpl_EditorImpl_putBoolean=" + func_SharedPreferencesImpl_EditorImpl_putBoolean)
    if (func_SharedPreferencesImpl_EditorImpl_putBoolean) {
      func_SharedPreferencesImpl_EditorImpl_putBoolean.implementation = function (key, value) {
        var funcName = "SharedPreferencesImpl.EditorImpl.putBoolean"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.putBoolean(key, value)
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }

    // public Editor putFloat(String key, float value) {
    // public android.content.SharedPreferences$Editor android.app.SharedPreferencesImpl$EditorImpl.putFloat(java.lang.String,float)
    var func_SharedPreferencesImpl_EditorImpl_putFloat = cls_SharedPreferencesImpl_EditorImpl.putFloat
    console.log("func_SharedPreferencesImpl_EditorImpl_putFloat=" + func_SharedPreferencesImpl_EditorImpl_putFloat)
    if (func_SharedPreferencesImpl_EditorImpl_putFloat) {
      func_SharedPreferencesImpl_EditorImpl_putFloat.implementation = function (key, value) {
        var funcName = "SharedPreferencesImpl.EditorImpl.putFloat"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.putFloat(key, value)
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }

    // public Editor putInt(String key, int value) {
    // public android.content.SharedPreferences$Editor android.app.SharedPreferencesImpl$EditorImpl.putInt(java.lang.String,int)
    var func_SharedPreferencesImpl_EditorImpl_putInt = cls_SharedPreferencesImpl_EditorImpl.putInt
    console.log("func_SharedPreferencesImpl_EditorImpl_putInt=" + func_SharedPreferencesImpl_EditorImpl_putInt)
    if (func_SharedPreferencesImpl_EditorImpl_putInt) {
      func_SharedPreferencesImpl_EditorImpl_putInt.implementation = function (key, value) {
        var funcName = "SharedPreferencesImpl.EditorImpl.putInt"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.putInt(key, value)
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }

  }

  static SharedPreferencesImpl() {
    var clsName_SharedPreferencesImpl = "android.app.SharedPreferencesImpl"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_SharedPreferencesImpl)

    var cls_SharedPreferencesImpl = Java.use(clsName_SharedPreferencesImpl)
    console.log("cls_SharedPreferencesImpl=" + cls_SharedPreferencesImpl)

    const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    // const curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // public Map<String, ?> getAll() {
    // public java.util.Map android.app.SharedPreferencesImpl.getAll()
    var func_SharedPreferencesImpl_getAll = cls_SharedPreferencesImpl.getAll
    console.log("func_SharedPreferencesImpl_getAll=" + func_SharedPreferencesImpl_getAll)
    if (func_SharedPreferencesImpl_getAll) {
      func_SharedPreferencesImpl_getAll.implementation = function () {
        var funcName = "SharedPreferencesImpl.getAll"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retMap = this.getAll()
        console.log(funcName + " => retMap=" + FridaAndroidUtil.mapToStr(retMap))
        return retMap
      }
    }

    // public Editor edit() {
    // public android.app.SharedPreferencesImpl$Editor android.app.SharedPreferencesImpl.edit()
    var func_SharedPreferencesImpl_edit = cls_SharedPreferencesImpl.edit
    console.log("func_SharedPreferencesImpl_edit=" + func_SharedPreferencesImpl_edit)
    if (func_SharedPreferencesImpl_edit) {
      func_SharedPreferencesImpl_edit.implementation = function () {
        var funcName = "SharedPreferencesImpl.edit"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.edit()
        console.log(funcName + " => retEditor=" + retEditor)
        FridaAndroidUtil.printClass_SharedPreferencesImpl_EditorImpl(retEditor, funcName)
        return retEditor
      }
    }

    // public long getLong(String key, long defValue)
    // public long android.app.SharedPreferencesImpl.getLong(java.lang.String,long)
    var func_SharedPreferencesImpl_getLong = cls_SharedPreferencesImpl.getLong
    console.log("func_SharedPreferencesImpl_getLong=" + func_SharedPreferencesImpl_getLong)
    if (func_SharedPreferencesImpl_getLong) {
      func_SharedPreferencesImpl_getLong.implementation = function (key, defValue) {
        var funcName = "SharedPreferencesImpl.getLong"
        var funcParaDict = {
          "key": key,
          "defValue": defValue,
        }
        curLogFunc(funcName, funcParaDict)
        
        var funcCallStr = `${funcName}(key=${key},defValue=${defValue})`
        var retLong = this.getLong(key, defValue)
        console.log(`${funcCallStr} => retLong=${retLong}`)

        // // for debug: emulate can NOT get checkin related SharedPreferencesImpl getLong values
        // if (JsUtil.isItemInList(key, HookAppJava_GMS.checkinKeyList)) {
        //   retLong = defValue
        //   var dbgStr = "for debug: emulate can NOT get checkin related SharedPreferencesImpl getLong values"
        //   console.log(dbgStr + " " + funcCallStr + " => retLong=" + retLong)
        // }

        return retLong
      }
    }

    // public String getString(String key, String defValue)
    // public java.lang.String android.app.SharedPreferencesImpl.getString(java.lang.String,java.lang.String)
    var func_SharedPreferencesImpl_getString = cls_SharedPreferencesImpl.getString
    console.log("func_SharedPreferencesImpl_getString=" + func_SharedPreferencesImpl_getString)
    if (func_SharedPreferencesImpl_getString) {
      func_SharedPreferencesImpl_getString.implementation = function (key, defValue) {
        var funcName = "SharedPreferencesImpl.getString"
        var funcParaDict = {
          "key": key,
          "defValue": defValue,
        }
        curLogFunc(funcName, funcParaDict)

        var retStr = this.getString(key, defValue)
        console.log(`${funcName}(key=${key},defValue=${defValue}) => retStr=${retStr}`)

        // // for debug: emulate can NOT get checkin related SharedPreferencesImpl getString values
        // if (JsUtil.isItemInList(key, HookAppJava_GMS.checkinKeyList)) {
        //   retStr = defValue
        //   var dbgStr = "for debug: emulate can NOT get checkin related SharedPreferencesImpl getString values"
        //   console.log(dbgStr + " " + funcName + " => retStr=" + retStr)
        // }

        return retStr
      }
    }

    // public Editor edit()
    // public android.app.SharedPreferencesImpl$Editor android.app.SharedPreferencesImpl.edit()
    var func_SharedPreferencesImpl_edit = cls_SharedPreferencesImpl.edit
    console.log("func_SharedPreferencesImpl_edit=" + func_SharedPreferencesImpl_edit)
    if (func_SharedPreferencesImpl_edit) {
      func_SharedPreferencesImpl_edit.implementation = function () {
        var funcName = "SharedPreferencesImpl.edit"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.edit()
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }


  }

  static File(callback_isShowLog=null) {
    var className_File = FridaAndroidUtil.clsName_File
    // FridaAndroidUtil.printClassAllMethodsFields(className_File)

    var cls_File = Java.use(className_File)
    console.log("cls_File=" + cls_File)

    // Error: File(): specified argument types do not match any of:
    // .overload('java.lang.String')
    // .overload('java.net.URI')
    // .overload('java.io.File', 'java.lang.String')
    // .overload('java.lang.String', 'int')
    // .overload('java.lang.String', 'java.io.File')
    // .overload('java.lang.String', 'java.lang.String')

    // File(String pathname)
    var func_File_ctor_1pp = cls_File.$init.overload('java.lang.String')
    console.log("func_File_ctor_1pp=" + func_File_ctor_1pp)
    if (func_File_ctor_1pp) {
      func_File_ctor_1pp.implementation = function (pathname) {
        var funcName = "File_1pp"
        var funcParaDict = {
          "pathname": pathname,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        // // for debug: tmp use previould check to bypass new File
        // pathname = "" // hook bypass return empty File by empty filename

        this.$init(pathname)
        var newFile_1pp = this
        if (isShowLog) {
          console.log(`${funcName}(${pathname}) => newFile_1pp=${newFile_1pp}`)
        }
        return
      }
    }

    // File(URI uri)
    // 
    var func_File_ctor_1pu = cls_File.$init.overload('java.net.URI')
    console.log("func_File_ctor_1pu=" + func_File_ctor_1pu)
    if (func_File_ctor_1pu) {
      func_File_ctor_1pu.implementation = function (uri) {
        var funcName = "File_1pu"
        var funcParaDict = {
          "uri": uri,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        this.$init(uri)
        if (isShowLog) {
          var newFile_1pu = this
          console.log(funcName + " => newFile_1pu=" + newFile_1pu)
        }
        return
      }
    }

    // String getAbsolutePath()
    // 
    var func_File_getAbsolutePath = cls_File.getAbsolutePath
    console.log("func_File_getAbsolutePath=" + func_File_getAbsolutePath)
    if (func_File_getAbsolutePath) {
      func_File_getAbsolutePath.implementation = function () {
        var funcName = "File.getAbsolutePath"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retAbsolutePath = this.getAbsolutePath()
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retAbsolutePath=${retAbsolutePath}`)
        return retAbsolutePath
      }
    }

    // File getParentFile()
    // 
    var func_File_getParentFile = cls_File.getParentFile
    console.log("func_File_getParentFile=" + func_File_getParentFile)
    if (func_File_getParentFile) {
      func_File_getParentFile.implementation = function () {
        var funcName = "File.getParentFile"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retParentFile = this.getParentFile()
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retParentFile=${retParentFile}`)
        return retParentFile
      }
    }

    // public boolean exists()
    // 
    var func_File_exists = cls_File.exists
    console.log("func_File_exists=" + func_File_exists)
    if (func_File_exists) {
      func_File_exists.implementation = function () {
        var funcName = "File.exists"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var fileAbsPath = this.getAbsolutePath()
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} fileAbsPath=${fileAbsPath}`)
        var retBoolean = this.exists()
        if(isShowLog){
          console.log(funcName + " => retBoolean=" + retBoolean + ",  fileAbsPath=" + fileAbsPath)
        }
        return retBoolean
      }
    }

  }

  static String(func_isShowLog=null) {
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
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)
        this.$init(original)
        return
      }
    }

    // String(byte[] bytes, Charset charset)
    // 
    var func_String_ctor_2pbc = cls_String.$init.overload('[B', 'java.nio.charset.Charset')
    console.log("func_String_ctor_2pbc=" + func_String_ctor_2pbc)
    if (func_String_ctor_2pbc) {
      func_String_ctor_2pbc.implementation = function (bytes, charset) {
        var funcName = "String(bytes,charset)"
        var funcParaDict = {
          "bytes": bytes,
          "charset": charset,
        }
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

        this.$init(bytes, charset)
        var newString_2pbc = this
        console.log(funcName + " => newString_2pbc=" + newString_2pbc)
        return
      }
    }

    // String(byte[] bytes, String charsetName)
    // 
    var func_String_ctor_2pbs = cls_String.$init.overload('[B', 'java.lang.String')
    console.log("func_String_ctor_2pbs=" + func_String_ctor_2pbs)
    if (func_String_ctor_2pbs) {
      func_String_ctor_2pbs.implementation = function (bytes, charsetName) {
        var funcName = "String(bytes,charsetName)"
        var funcParaDict = {
          "bytes": bytes,
          "charsetName": charsetName,
        }
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

        this.$init(bytes, charsetName)
        var newString_2pbs = this
        console.log(funcName + " => newString_2pbs=" + newString_2pbs)
        return
      }
    }

    // // public boolean equals(Object anObject)
    // // public boolean java.lang.String.equals(java.lang.Object)
    // var func_String_equals = cls_String.equals
    // console.log("func_String_equals=" + func_String_equals)
    // if (func_String_equals) {
    //   func_String_equals.implementation = function (anObject) {
    //     var funcName = "String.equals(anObject)"
    //     var funcParaDict = {
    //       "anObject": anObject,
    //     }

    //     var isPrintStack = false
    //     if(null != callback_String_equals) {
    //       isPrintStack = callback_String_equals(anObject)
    //     }

    //     if(isPrintStack){
    //       FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
    //     }

    //     return this.equals(anObject)
    //   }
    // }

    // static String format(Locale l, String format, Object... args)
    // public static java.lang.String java.lang.String.format(java.util.Locale,java.lang.String,java.lang.Object[])
    var func_String_format_3plfa = cls_String.format.overload('java.util.Locale', 'java.lang.String', '[Ljava.lang.Object;')
    console.log("func_String_format_3plfa=" + func_String_format_3plfa)
    if (func_String_format_3plfa) {
      func_String_format_3plfa.implementation = function (l, format, args) {
        var funcName = "String.format_3plfa"
        var funcParaDict = {
          "l": l,
          "format": format,
          "args": args,
        }

        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var retString_3plfa = this.format(l, format, args)

        // var isShowLog = true
        var isShowLog = false

        if(func_isShowLog != null) {
          isShowLog = func_isShowLog(retString_3plfa)
          // isShowLog = func_isShowLog(format)
        }

        if (isShowLog){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
          // FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)  
        }

        if (isShowLog){
          console.log(funcCallAndStackStr)
          console.log(funcName + " => retString_3plfa=" + retString_3plfa)
        }

        return retString_3plfa
      }
    }

    // static String format(String format, Object... args)
    // public static java.lang.String java.lang.String.format(java.lang.String,java.lang.Object[])
    var func_String_format_2pfa = cls_String.format.overload('java.lang.String', '[Ljava.lang.Object;')
    console.log("func_String_format_2pfa=" + func_String_format_2pfa)
    if (func_String_format_2pfa) {
      func_String_format_2pfa.implementation = function (format, args) {
        var funcName = "String.format_2pfa"
        var funcParaDict = {
          "format": format,
          "args": args,
        }

        var isShowLog = false
        if(func_isShowLog != null) {
          isShowLog = func_isShowLog(format)
        }

        if (isShowLog){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        var retString_2pfa = this.format(format, args)

        if (isShowLog){
          console.log(funcName + " => retString_2pfa=" + retString_2pfa)
        }

        return retString_2pfa
      }
    }

    // String[] split(String regex)
    // public java.lang.String[] java.lang.String.split(java.lang.String)
    var func_String_split_1pr = cls_String.split.overload('java.lang.String')
    console.log("func_String_split_1pr=" + func_String_split_1pr)
    if (func_String_split_1pr) {
      func_String_split_1pr.implementation = function (regex) {
        var funcName = "String.split_1pr"
        var funcParaDict = {
          "regex": regex,
        }

        var isShowLog = false
        if(func_isShowLog != null) {
          isShowLog = func_isShowLog(regex)
        }

        if (isShowLog){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        var retString_1pr = this.split(regex)

        if (isShowLog){
          console.log(funcName + " => retString_1pr=" + retString_1pr)
        }

        return retString_1pr
      }
    }

    // static String valueOf(long l)
    // public static java.lang.String java.lang.String.valueOf(long)
    var func_String_valueOf_1pl = cls_String.valueOf.overload('long')
    console.log("func_String_valueOf_1pl=" + func_String_valueOf_1pl)
    if (func_String_valueOf_1pl) {
      func_String_valueOf_1pl.implementation = function (l) {
        var funcName = "String.valueOf_1pl"
        var funcParaDict = {
          "l": l,
        }

        var isShowLog = false
        if(func_isShowLog != null) {
          isShowLog = func_isShowLog(l.toString())
        }

        if (isShowLog){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        var retString_1pl = this.valueOf(l)

        if (isShowLog){
          console.log(funcName + " => retString_1pl=" + retString_1pl)
        }

        return retString_1pl
      }
    }

  }

  static URL(callback_isShowLog=null) {
    var clsName_URL = "java.net.URL"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_URL)

    var cls_URL = Java.use(clsName_URL)
    console.log("cls_URL=" + cls_URL)

    // const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    const curLogFunc = FridaAndroidUtil.printFunctionCallStr
    
    // public URL(String spec)
    // 
    var func_URL_ctor_1ps = cls_URL.$init.overload('java.lang.String')
    console.log("func_URL_ctor_1ps=" + func_URL_ctor_1ps)
    if (func_URL_ctor_1ps) {
      func_URL_ctor_1ps.implementation = function (spec) {
        var funcName = "URL_1ps"
        var funcParaDict = {
          "spec": spec,
        }
        // curLogFunc(funcName, funcParaDict)
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        this.$init(spec)
        var newURL_1ps = this
        // if (isShowLog) {
          console.log(funcName + " => newURL_1ps=" + newURL_1ps)
        // }
        return
      }
    }

    // String getHost()
    // 
    var func_URL_getHost = cls_URL.getHost
    console.log("func_URL_getHost=" + func_URL_getHost)
    if (func_URL_getHost) {
      func_URL_getHost.implementation = function () {
        var funcName = "URL.getHost"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retHost = this.getHost()
        console.log(funcName + " => retHost=" + retHost)
        return retHost
      }
    }

    // String getPath()
    // 
    var func_URL_getPath = cls_URL.getPath
    console.log("func_URL_getPath=" + func_URL_getPath)
    if (func_URL_getPath) {
      func_URL_getPath.implementation = function () {
        var funcName = "URL.getPath"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retPath = this.getPath()
        console.log(funcName + " => retPath=" + retPath)
        return retPath
      }
    }

    // int getPort()
    // 
    var func_URL_getPort = cls_URL.getPort
    console.log("func_URL_getPort=" + func_URL_getPort)
    if (func_URL_getPort) {
      func_URL_getPort.implementation = function () {
        var funcName = "URL.getPort"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retPort = this.getPort()
        console.log(funcName + " => retPort=" + retPort)
        return retPort
      }
    }

    // String getProtocol()
    // 
    var func_URL_getProtocol = cls_URL.getProtocol
    console.log("func_URL_getProtocol=" + func_URL_getProtocol)
    if (func_URL_getProtocol) {
      func_URL_getProtocol.implementation = function () {
        var funcName = "URL.getProtocol"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retProtocol = this.getProtocol()
        console.log(funcName + " => retProtocol=" + retProtocol)
        return retProtocol
      }
    }

    // String getQuery()
    // 
    var func_URL_getQuery = cls_URL.getQuery
    console.log("func_URL_getQuery=" + func_URL_getQuery)
    if (func_URL_getQuery) {
      func_URL_getQuery.implementation = function () {
        var funcName = "URL.getQuery"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retQuery = this.getQuery()
        console.log(funcName + " => retQuery=" + retQuery)
        return retQuery
      }
    }

    // public URLConnection openConnection()
    // public java.net.URLConnection java.net.URL.openConnection() throws java.io.IOException
    var func_URL_openConnection_0p = cls_URL.openConnection.overload()
    console.log("func_URL_openConnection_0p=" + func_URL_openConnection_0p)
    if (func_URL_openConnection_0p) {
      func_URL_openConnection_0p.implementation = function () {
        var funcName = "URL.openConnection"
        var funcParaDict = {}
        // curLogFunc(funcName, funcParaDict)
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retUrlConn = this.openConnection()
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retUrlConn=${retUrlConn}`)
        return retUrlConn
      }
    }

  }

  static GZIPOutputStream() {
    var clsName_GZIPOutputStream = "java.util.zip.GZIPOutputStream"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_GZIPOutputStream)

    var cls_GZIPOutputStream = Java.use(clsName_GZIPOutputStream)
    console.log("cls_GZIPOutputStream=" + cls_GZIPOutputStream)

    
    // GZIPOutputStream(OutputStream out)
    // 
    var func_GZIPOutputStream_ctor_1po = cls_GZIPOutputStream.$init.overload('java.io.OutputStream')
    console.log("func_GZIPOutputStream_ctor_1po=" + func_GZIPOutputStream_ctor_1po)
    if (func_GZIPOutputStream_ctor_1po) {
      func_GZIPOutputStream_ctor_1po.implementation = function (out) {
        var funcName = "GZIPOutputStream_1po"
        var funcParaDict = {
          "out": out,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(out)
        var newGZIPOutputStream_1po = this
        console.log(funcName + " => newGZIPOutputStream_1po=" + newGZIPOutputStream_1po)
        return
      }
    }

    // void write(byte[] buf, int off, int len)
    // public synchronized void java.util.zip.GZIPOutputStream.write(byte[],int,int) throws java.io.IOException
    var func_GZIPOutputStream_write = cls_GZIPOutputStream.write
    console.log("func_GZIPOutputStream_write=" + func_GZIPOutputStream_write)
    if (func_GZIPOutputStream_write) {
      func_GZIPOutputStream_write.implementation = function (buf, off, len) {
        var funcName = "GZIPOutputStream.write"
        var funcParaDict = {
          "buf": buf,
          "off": off,
          "len": len,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.write(buf, off, len)
      }
    }

    // void	finish()
    // public void java.util.zip.GZIPOutputStream.finish() throws java.io.IOException
    var func_GZIPOutputStream_finish = cls_GZIPOutputStream.finish
    console.log("func_GZIPOutputStream_finish=" + func_GZIPOutputStream_finish)
    if (func_GZIPOutputStream_finish) {
      func_GZIPOutputStream_finish.implementation = function () {
        var funcName = "GZIPOutputStream.finish"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var crc = this.crc.vaue
        console.log(funcName + ": crc=" + crc)

        return this.finish()
      }
    }

    // void	close()
    // 
    var func_GZIPOutputStream_close = cls_GZIPOutputStream.close
    console.log("func_GZIPOutputStream_close=" + func_GZIPOutputStream_close)
    if (func_GZIPOutputStream_close) {
      func_GZIPOutputStream_close.implementation = function () {
        var funcName = "GZIPOutputStream.close"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var crc = this.crc.vaue
        console.log(funcName + ": crc=" + crc)

        return this.close()
      }
    }

  }

  static DeflaterOutputStream() {
    var clsName_DeflaterOutputStream = "java.util.zip.DeflaterOutputStream"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_DeflaterOutputStream)

    var cls_DeflaterOutputStream = Java.use(clsName_DeflaterOutputStream)
    console.log("cls_DeflaterOutputStream=" + cls_DeflaterOutputStream)

    // void	close()
    // public void java.util.zip.DeflaterOutputStream.close() throws java.io.IOException
    var func_DeflaterOutputStream_close = cls_DeflaterOutputStream.close
    console.log("func_DeflaterOutputStream_close=" + func_DeflaterOutputStream_close)
    if (func_DeflaterOutputStream_close) {
      func_DeflaterOutputStream_close.implementation = function () {
        var funcName = "DeflaterOutputStream.close"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var buffer = this.buf.vaue
        console.log(funcName + ": buffer=" + buffer)
        var deflater = this.def.vaue
        console.log(funcName + ": deflater=" + deflater)

        // var copiedDos = this.clone()
        // console.log("DeflaterOutputStream: copiedDos=" + copiedDos)
        // if (copiedDos){
        //   var copiedDosBuf = copiedDos.buf
        //   console.log("DeflaterOutputStream: copiedDosBuf=" + copiedDosBuf)
        //   if(copiedDosBuf){
        //     var buffer = copiedDosBuf.value
        //     console.log("DeflaterOutputStream: buffer=" + buffer)
        //   }
        //   var copiedDosDef = copiedDos.def
        //   console.log("DeflaterOutputStream: copiedDosDef=" + copiedDosDef)
        //   if(copiedDosDef){
        //     var deflater = copiedDosDef.value
        //     console.log("DeflaterOutputStream: deflater=" + deflater)  
        //   }
        // }

        return this.close()
      }
    }

    // protected void	deflate()
    // protected void java.util.zip.DeflaterOutputStream.deflate() throws java.io.IOException
    var func_DeflaterOutputStream_deflate = cls_DeflaterOutputStream.deflate
    console.log("func_DeflaterOutputStream_deflate=" + func_DeflaterOutputStream_deflate)
    if (func_DeflaterOutputStream_deflate) {
      func_DeflaterOutputStream_deflate.implementation = function () {
        var funcName = "DeflaterOutputStream.deflate"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var buffer = this.buf.vaue
        console.log(funcName + ": buffer=" + buffer)
        var deflater = this.def.vaue
        console.log(funcName + ": deflater=" + deflater)

        return this.deflate()
      }
    }

    // void	finish()
    // public void java.util.zip.DeflaterOutputStream.finish() throws java.io.IOException
    var func_DeflaterOutputStream_finish = cls_DeflaterOutputStream.finish
    console.log("func_DeflaterOutputStream_finish=" + func_DeflaterOutputStream_finish)
    if (func_DeflaterOutputStream_finish) {
      func_DeflaterOutputStream_finish.implementation = function () {
        var funcName = "DeflaterOutputStream.finish"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var buffer = this.buf.vaue
        console.log(funcName + ": buffer=" + buffer)
        var deflater = this.def.vaue
        console.log(funcName + ": deflater=" + deflater)

        return this.finish()
      }
    }

    // void	flush()
    // public void java.util.zip.DeflaterOutputStream.flush() throws java.io.IOException
    var func_DeflaterOutputStream_flush = cls_DeflaterOutputStream.flush
    console.log("func_DeflaterOutputStream_flush=" + func_DeflaterOutputStream_flush)
    if (func_DeflaterOutputStream_flush) {
      func_DeflaterOutputStream_flush.implementation = function () {
        var funcName = "DeflaterOutputStream.flush"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var buffer = this.buf.vaue
        console.log(funcName + ": buffer=" + buffer)
        var deflater = this.def.vaue
        console.log(funcName + ": deflater=" + deflater)

        return this.flush()
      }
    }

  }

  static BufferedOutputStream() {
    var clsName_BufferedOutputStream = "java.io.BufferedOutputStream"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_BufferedOutputStream)

    var cls_BufferedOutputStream = Java.use(clsName_BufferedOutputStream)
    console.log("cls_BufferedOutputStream=" + cls_BufferedOutputStream)

    // void write(int b)
    // public synchronized void java.io.BufferedOutputStream.write(int) throws java.io.IOException
    var func_BufferedOutputStream_write_1pi = cls_BufferedOutputStream.write.overload('int')
    console.log("func_BufferedOutputStream_write_1pi=" + func_BufferedOutputStream_write_1pi)
    if (func_BufferedOutputStream_write_1pi) {
      func_BufferedOutputStream_write_1pi.implementation = function (b) {
        var funcName = "BufferedOutputStream.write_1pi"
        var funcParaDict = {
          "b": b,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + ": curBufStr=" + curBufStr)

        var buf = this.buf.value
        console.log(funcName + ": buf=" + buf)
        var count = this.count.value
        console.log(funcName + ": count=" + count)

        return this.write(b)
      }
    }

    // void write(byte[] b, int off, int len)
    // public synchronized void java.io.BufferedOutputStream.write(byte[],int,int) throws java.io.IOException
    var func_BufferedOutputStream_write_3pbii = cls_BufferedOutputStream.write.overload('[B', 'int', 'int')
    console.log("func_BufferedOutputStream_write_3pbii=" + func_BufferedOutputStream_write_3pbii)
    if (func_BufferedOutputStream_write_3pbii) {
      func_BufferedOutputStream_write_3pbii.implementation = function (b, off, len) {
        var funcName = "BufferedOutputStream.write_3pbii"
        var funcParaDict = {
          "b": b,
          "off": off,
          "len": len,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + ": curBufStr=" + curBufStr)

        var buf = this.buf.value
        console.log(funcName + ": buf=" + buf)
        var count = this.count.value
        console.log(funcName + ": count=" + count)

        return this.write(b, off, len)
      }
    }

    // void flush()
    // public synchronized void java.io.BufferedOutputStream.flush() throws java.io.IOException
    var func_BufferedOutputStream_flush = cls_BufferedOutputStream.flush
    console.log("func_BufferedOutputStream_flush=" + func_BufferedOutputStream_flush)
    if (func_BufferedOutputStream_flush) {
      func_BufferedOutputStream_flush.implementation = function () {
        var funcName = "BufferedOutputStream.flush"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log("before " + funcName + ": curBufStr=" + curBufStr)
        
        var buf = this.buf.value
        console.log("before " + funcName + ": buf=" + buf)
        var count = this.count.value
        console.log("before " + funcName + ": count=" + count)

        this.flush()

        var curBufStr = this.toString()
        console.log("after  " + funcName + ": curBufStr=" + curBufStr)
        
        var buf = this.buf.value
        console.log("after  " + funcName + ": buf=" + buf)
        var count = this.count.value
        console.log("after  " + funcName + ": count=" + count)

        return
      }
    }

    // void	close()
    // 
    var func_BufferedOutputStream_close = cls_BufferedOutputStream.close
    console.log("func_BufferedOutputStream_close=" + func_BufferedOutputStream_close)
    if (func_BufferedOutputStream_close) {
      func_BufferedOutputStream_close.implementation = function () {
        var funcName = "BufferedOutputStream.close"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var buf = this.buf.value
        console.log(funcName + " buf=" + buf)
        var count = this.count.value
        console.log(funcName + " count=" + count)

        var curBufStr = this.toString()
        console.log(funcName + " curBufStr=" + curBufStr)
        
        // var copiedBos = this.clone()
        // console.log("BufferedOutputStream: copiedBos=" + copiedBos)
        // if (copiedBos){
        //   var copiedBosBuf = copiedBos.buf
        //   console.log("BufferedOutputStream: copiedBosBuf=" + copiedBosBuf)
        //   if(copiedBosBuf){
        //     var buffer = copiedBosBuf.value
        //     console.log("BufferedOutputStream: buffer=" + buffer)
        //   }
        //   var copiedBosCount = copiedBos.count
        //   console.log("BufferedOutputStream: copiedBosCount=" + copiedBosCount)
        //   if(copiedBosCount){
        //     var count = copiedBosCount.value
        //     console.log("BufferedOutputStream: count=" + count)  
        //   }
        // }

        return this.close()
      }
    }

  }

  static FilterOutputStream() {
    var clsName_FilterOutputStream = "java.io.FilterOutputStream"
    FridaAndroidUtil.printClassAllMethodsFields(clsName_FilterOutputStream)

    var cls_FilterOutputStream = Java.use(clsName_FilterOutputStream)
    console.log("cls_FilterOutputStream=" + cls_FilterOutputStream)

    // void	close()
    // public void java.io.FilterOutputStream.close() throws java.io.IOException
    var func_FilterOutputStream_close = cls_FilterOutputStream.close
    console.log("func_FilterOutputStream_close=" + func_FilterOutputStream_close)
    if (func_FilterOutputStream_close) {
      func_FilterOutputStream_close.implementation = function () {
        var funcName = "FilterOutputStream.close"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + " curBufStr=" + curBufStr)
        var outStream = this.out.value
        console.log(funcName + " outStream=" + outStream)
        // FilterOutputStream.close outStream=buffer(com.android.okhttp.internal.http.RetryableSink@d96946b).outputStream()

        return this.close()
      }
    }

    // void	flush()
    // public void java.io.FilterOutputStream.flush() throws java.io.IOException
    var func_FilterOutputStream_flush = cls_FilterOutputStream.flush
    console.log("func_FilterOutputStream_flush=" + func_FilterOutputStream_flush)
    if (func_FilterOutputStream_flush) {
      func_FilterOutputStream_flush.implementation = function () {
        var funcName = "FilterOutputStream.flush"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + ": curBufStr=" + curBufStr)
        var outStream = this.out.value
        console.log(funcName + ": outStream=" + outStream)

        return this.close()
      }
    }

  }

  static RetryableSink() {
    // FridaAndroidUtil.printClassAllMethodsFields(FridaAndroidUtil.clsName_RetryableSink)

    var cls_RetryableSink = Java.use(FridaAndroidUtil.clsName_RetryableSink)
    console.log("cls_RetryableSink=" + cls_RetryableSink)

    // @Override public void close() throws IOException {
    // public void com.android.okhttp.internal.http.RetryableSink.close() throws java.io.IOException
    var func_RetryableSink_close = cls_RetryableSink.close
    console.log("func_RetryableSink_close=" + func_RetryableSink_close)
    if (func_RetryableSink_close) {
      func_RetryableSink_close.implementation = function () {
        var funcName = "RetryableSink.close"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        FridaAndroidUtil.printClass_RetryableSink(this, `Before ${funcName}` )

        return this.close()
      }
    }

    // @Override public void write(Buffer source, long byteCount) throws IOException {
    // public void com.android.okhttp.internal.http.RetryableSink.write(com.android.okhttp.okio.Buffer,long) throws java.io.IOException
    var func_RetryableSink_write = cls_RetryableSink.write
    console.log("func_RetryableSink_write=" + func_RetryableSink_write)
    if (func_RetryableSink_write) {
      func_RetryableSink_write.implementation = function (source, byteCount) {
        var funcName = "RetryableSink.write"
        var funcParaDict = {
          "source": source,
          "byteCount": byteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var content = this.content.value
        console.log(funcName + " content=" + content)

        return this.write(source, byteCount)
      }
    }

    // @Override public void flush() throws IOException {
    // public void com.android.okhttp.internal.http.RetryableSink.flush() throws java.io.IOException
    var func_RetryableSink_flush = cls_RetryableSink.flush
    console.log("func_RetryableSink_flush=" + func_RetryableSink_flush)
    if (func_RetryableSink_flush) {
      func_RetryableSink_flush.implementation = function () {
        var funcName = "RetryableSink.flush"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var content = this.content.value
        console.log(funcName + " content=" + content)

        return this.flush()
      }
    }

    // public long contentLength() throws IOException {
    // public long com.android.okhttp.internal.http.RetryableSink.contentLength() throws java.io.IOException
    var func_RetryableSink_contentLength = cls_RetryableSink.contentLength
    console.log("func_RetryableSink_contentLength=" + func_RetryableSink_contentLength)
    if (func_RetryableSink_contentLength) {
      func_RetryableSink_contentLength.implementation = function () {
        var funcName = "RetryableSink.contentLength"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        
        var retContentLength = this.contentLength()
        console.log(funcName + " => retContentLength=" + retContentLength)

        return retContentLength
      }
    }

    // public void writeToSocket(Sink socketOut) throws IOException {
    // public void com.android.okhttp.internal.http.RetryableSink.writeToSocket(com.android.okhttp.okio.Sink) throws java.io.IOException
    var func_RetryableSink_writeToSocket = cls_RetryableSink.writeToSocket
    console.log("func_RetryableSink_writeToSocket=" + func_RetryableSink_writeToSocket)
    if (func_RetryableSink_writeToSocket) {
      func_RetryableSink_writeToSocket.implementation = function (socketOut) {
        var funcName = "RetryableSink.writeToSocket"
        var funcParaDict = {
          "socketOut": socketOut,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var content = this.content.value
        console.log(funcName + " content=" + content)

        return this.writeToSocket(socketOut)
      }
    }

  }

  static Buffer() {
    // var clsName_Buffer = "okio.Buffer"
    FridaAndroidUtil.printClassAllMethodsFields(FridaAndroidUtil.clsName_Buffer)

    var cls_Buffer = Java.use(FridaAndroidUtil.clsName_Buffer)
    console.log("cls_Buffer=" + cls_Buffer)

    // @Override public int read(byte[] sink) {
    // public int com.android.okhttp.okio.Buffer.read(byte[])
    var func_Buffer_read_1ps = cls_Buffer.read.overload('[B')
    console.log("func_Buffer_read_1ps=" + func_Buffer_read_1ps)
    if (func_Buffer_read_1ps) {
      func_Buffer_read_1ps.implementation = function (sink) {
        var funcName = "okio.Buffer.read_1ps"
        var funcParaDict = {
          "sink": sink,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + " curBufStr=" + curBufStr)
        var head = this.head.value
        console.log(funcName + " head=" + head)
        var size = this.size.value
        console.log(funcName + " size=" + size)

        var readCnt = this.read(sink)
        console.log(funcName + " => readCnt=" + readCnt)
        return readCnt
      }
    }

    // @Override public int read(byte[] sink, int offset, int byteCount) {
    // public int com.android.okhttp.okio.Buffer.read(byte[],int,int)
    var func_Buffer_read_3psob = cls_Buffer.read.overload('[B', 'int', 'int')
    console.log("func_Buffer_read_3psob=" + func_Buffer_read_3psob)
    if (func_Buffer_read_3psob) {
      func_Buffer_read_3psob.implementation = function (sink, offset, byteCount) {
        var funcName = "okio.Buffer.read_3psob"
        var funcParaDict = {
          "sink": sink,
          "offset": offset,
          "byteCount": byteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + " curBufStr=" + curBufStr)
        var head = this.head.value
        console.log(funcName + " head=" + head)
        var size = this.size.value
        console.log(funcName + " size=" + size)

        var readCnt = this.read(sink, offset, byteCount)
        console.log(funcName + " => readCnt=" + readCnt)
        return readCnt
      }
    }

    // @Override public long read(Buffer sink, long byteCount) {
    // public long com.android.okhttp.okio.Buffer.read(com.android.okhttp.okio.Buffer,long)
    var func_Buffer_read_2psb = cls_Buffer.read.overload('com.android.okhttp.okio.Buffer', 'long')
    console.log("func_Buffer_read_2psb=" + func_Buffer_read_2psb)
    if (func_Buffer_read_2psb) {
      func_Buffer_read_2psb.implementation = function (sink, byteCount) {
        var funcName = "okio.Buffer.read_2psb"
        var funcParaDict = {
          "sink": sink,
          "byteCount": byteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + " curBufStr=" + curBufStr)
        var head = this.head.value
        console.log(funcName + " head=" + head)
        var size = this.size.value
        console.log(funcName + " size=" + size)

        var readCnt = this.read(sink, byteCount)
        console.log(funcName + " => readCnt=" + readCnt)
        return readCnt
      }
    }

    // @Override public void readFully(byte[] sink) throws EOFException {
    // public void com.android.okhttp.okio.Buffer.readFully(byte[]) throws java.io.EOFException
    var func_Buffer_readFully_1ps = cls_Buffer.readFully.overload('[B')
    console.log("func_Buffer_readFully_1ps=" + func_Buffer_readFully_1ps)
    if (func_Buffer_readFully_1ps) {
      func_Buffer_readFully_1ps.implementation = function (sink) {
        var funcName = "okio.Buffer.readFully_1ps"
        var funcParaDict = {
          "sink": sink,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + " curBufStr=" + curBufStr)
        var head = this.head.value
        console.log(funcName + " head=" + head)
        var size = this.size.value
        console.log(funcName + " size=" + size)

        return this.readFully(sink)
      }
    }

    // @Override public void readFully(Buffer sink, long byteCount) throws EOFException {
    // public void com.android.okhttp.okio.Buffer.readFully(com.android.okhttp.okio.Buffer,long) throws java.io.EOFException
    var func_Buffer_readFully_2psb = cls_Buffer.readFully.overload('com.android.okhttp.okio.Buffer', 'long')
    console.log("func_Buffer_readFully_2psb=" + func_Buffer_readFully_2psb)
    if (func_Buffer_readFully_2psb) {
      func_Buffer_readFully_2psb.implementation = function (sink, byteCount) {
        var funcName = "okio.Buffer.readFully_2psb"
        var funcParaDict = {
          "sink": sink,
          "byteCount": byteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + " curBufStr=" + curBufStr)
        var head = this.head.value
        console.log(funcName + " head=" + head)
        var size = this.size.value
        console.log(funcName + " size=" + size)

        return this.readFully(sink, byteCount)
      }
    }

  }

  static TelephonyManager() {
    var clsName_TelephonyManager = "android.telephony.TelephonyManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_TelephonyManager)

    var cls_TelephonyManager = Java.use(clsName_TelephonyManager)
    console.log("cls_TelephonyManager=" + cls_TelephonyManager)
    
    // String getDeviceId()
    // public java.lang.String android.telephony.TelephonyManager.getDeviceId()
    var func_TelephonyManager_getDeviceId_0p = cls_TelephonyManager.getDeviceId.overload()
    console.log("func_TelephonyManager_getDeviceId_0p=" + func_TelephonyManager_getDeviceId_0p)
    if (func_TelephonyManager_getDeviceId_0p) {
      func_TelephonyManager_getDeviceId_0p.implementation = function () {
        var funcName = "TelephonyManager.getDeviceId_0p"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retDeviceId_0p = this.getDeviceId()
        console.log(funcName + " => retDeviceId_0p=" + retDeviceId_0p)
        return retDeviceId_0p
      }
    }

    // String getDeviceId(int slotIndex)
    // public java.lang.String android.telephony.TelephonyManager.getDeviceId(int)
    var func_TelephonyManager_getDeviceId_1ps = cls_TelephonyManager.getDeviceId.overload('int')
    console.log("func_TelephonyManager_getDeviceId_1ps=" + func_TelephonyManager_getDeviceId_1ps)
    if (func_TelephonyManager_getDeviceId_1ps) {
      func_TelephonyManager_getDeviceId_1ps.implementation = function (slotIndex) {
        var funcName = "TelephonyManager.getDeviceId_1ps"
        var funcParaDict = {
          "slotIndex": slotIndex,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retDeviceId_1ps = this.getDeviceId(slotIndex)
        console.log(funcName + " => retDeviceId_1ps=" + retDeviceId_1ps)
        return retDeviceId_1ps
      }
    }

    // String getImei(int slotIndex)
    // public java.lang.String android.telephony.TelephonyManager.getImei(int)
    var func_TelephonyManager_getImei_1ps = cls_TelephonyManager.getImei.overload('int')
    console.log("func_TelephonyManager_getImei_1ps=" + func_TelephonyManager_getImei_1ps)
    if (func_TelephonyManager_getImei_1ps) {
      func_TelephonyManager_getImei_1ps.implementation = function (slotIndex) {
        var funcName = "TelephonyManager.getImei(slotIndex)"
        var funcParaDict = {
          "slotIndex": slotIndex,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retImei_1ps = this.getImei(slotIndex)
        console.log(funcName + " => retImei_1ps=" + retImei_1ps)
        return retImei_1ps
      }
    }

    // String getImei()
    // public java.lang.String android.telephony.TelephonyManager.getImei()
    var func_TelephonyManager_getImei_0p = cls_TelephonyManager.getImei.overload()
    console.log("func_TelephonyManager_getImei_0p=" + func_TelephonyManager_getImei_0p)
    if (func_TelephonyManager_getImei_0p) {
      func_TelephonyManager_getImei_0p.implementation = function () {
        var funcName = "TelephonyManager.getImei()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retImei_0p = this.getImei()
        console.log(funcName + " => retImei_0p=" + retImei_0p)
        return retImei_0p
      }
    }

    // public String getMeid()
    // public java.lang.String android.telephony.TelephonyManager.getMeid()
    var func_TelephonyManager_getMeid_0p = cls_TelephonyManager.getMeid.overload()
    console.log("func_TelephonyManager_getMeid_0p=" + func_TelephonyManager_getMeid_0p)
    if (func_TelephonyManager_getMeid_0p) {
      func_TelephonyManager_getMeid_0p.implementation = function () {
        var funcName = "TelephonyManager.getMeid()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retMeid_0p = this.getMeid()
        console.log(funcName + " => retMeid_0p=" + retMeid_0p)
        return retMeid_0p
      }
    }

    // public String getMeid(int slotIndex)
    // public java.lang.String android.telephony.TelephonyManager.getMeid(int)
    var func_TelephonyManager_getMeid_1ps = cls_TelephonyManager.getMeid.overload('int')
    console.log("func_TelephonyManager_getMeid_1ps=" + func_TelephonyManager_getMeid_1ps)
    if (func_TelephonyManager_getMeid_1ps) {
      func_TelephonyManager_getMeid_1ps.implementation = function (slotIndex) {
        var funcName = "TelephonyManager.getMeid(slotIndex)"
        var funcParaDict = {
          "slotIndex": slotIndex,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retMeid_1ps = this.getMeid(slotIndex)
        console.log(funcName + " => retMeid_1ps=" + retMeid_1ps)
        return retMeid_1ps
      }
    }

    // public String getSimOperator()
    // public java.lang.String android.telephony.TelephonyManager.getSimOperator()
    var func_TelephonyManager_getSimOperator_0p = cls_TelephonyManager.getSimOperator.overload()
    console.log("func_TelephonyManager_getSimOperator_0p=" + func_TelephonyManager_getSimOperator_0p)
    if (func_TelephonyManager_getSimOperator_0p) {
      func_TelephonyManager_getSimOperator_0p.implementation = function () {
        var funcName = "TelephonyManager.getSimOperator()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retSimOperator_0p = this.getSimOperator()
        console.log(funcName + " => retSimOperator_0p=" + retSimOperator_0p)
        return retSimOperator_0p
      }
    }

    // public String getSimSerialNumber()
    // public java.lang.String android.telephony.TelephonyManager.getSimSerialNumber()
    var func_TelephonyManager_getSimSerialNumber_0p = cls_TelephonyManager.getSimSerialNumber.overload()
    console.log("func_TelephonyManager_getSimSerialNumber_0p=" + func_TelephonyManager_getSimSerialNumber_0p)
    if (func_TelephonyManager_getSimSerialNumber_0p) {
      func_TelephonyManager_getSimSerialNumber_0p.implementation = function () {
        var funcName = "TelephonyManager.getSimSerialNumber()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retSimSerialNumber_0p = this.getSimSerialNumber()
        console.log(funcName + " => retSimSerialNumber_0p=" + retSimSerialNumber_0p)
        return retSimSerialNumber_0p
      }
    }
    
    // public String getSubscriberId()
    // public java.lang.String android.telephony.TelephonyManager.getSubscriberId()
    var func_TelephonyManager_getSubscriberId_0p = cls_TelephonyManager.getSubscriberId.overload()
    console.log("func_TelephonyManager_getSubscriberId_0p=" + func_TelephonyManager_getSubscriberId_0p)
    if (func_TelephonyManager_getSubscriberId_0p) {
      func_TelephonyManager_getSubscriberId_0p.implementation = function () {
        var funcName = "TelephonyManager.getSubscriberId()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retSubscriberId_0p = this.getSubscriberId()
        console.log(funcName + " => retSubscriberId_0p=" + retSubscriberId_0p)
        return retSubscriberId_0p
      }
    }
    
    // public String getSimOperatorName()
    // public java.lang.String android.telephony.TelephonyManager.getSimOperatorName()
    var func_TelephonyManager_getSimOperatorName_0p = cls_TelephonyManager.getSimOperatorName.overload()
    console.log("func_TelephonyManager_getSimOperatorName_0p=" + func_TelephonyManager_getSimOperatorName_0p)
    if (func_TelephonyManager_getSimOperatorName_0p) {
      func_TelephonyManager_getSimOperatorName_0p.implementation = function () {
        var funcName = "TelephonyManager.getSimOperatorName()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retSimOperatorName_0p = this.getSimOperatorName()
        console.log(funcName + " => retSimOperatorName_0p=" + retSimOperatorName_0p)
        return retSimOperatorName_0p
      }
    }
    
    // public boolean isNetworkRoaming()
    // public boolean android.telephony.TelephonyManager.isNetworkRoaming()
    var func_TelephonyManager_isNetworkRoaming_0p = cls_TelephonyManager.isNetworkRoaming.overload()
    console.log("func_TelephonyManager_isNetworkRoaming_0p=" + func_TelephonyManager_isNetworkRoaming_0p)
    if (func_TelephonyManager_isNetworkRoaming_0p) {
      func_TelephonyManager_isNetworkRoaming_0p.implementation = function () {
        var funcName = "TelephonyManager.isNetworkRoaming()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var isNetRoaming_0p = this.isNetworkRoaming()
        console.log(funcName + " => isNetRoaming_0p=" + isNetRoaming_0p)
        return isNetRoaming_0p
      }
    }
    
    // public String getGroupIdLevel1()
    // public java.lang.String android.telephony.TelephonyManager.getGroupIdLevel1()
    var func_TelephonyManager_getGroupIdLevel1_0p = cls_TelephonyManager.getGroupIdLevel1.overload()
    console.log("func_TelephonyManager_getGroupIdLevel1_0p=" + func_TelephonyManager_getGroupIdLevel1_0p)
    if (func_TelephonyManager_getGroupIdLevel1_0p) {
      func_TelephonyManager_getGroupIdLevel1_0p.implementation = function () {
        var funcName = "TelephonyManager.getGroupIdLevel1()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var groupIdLevel1_0p = this.getGroupIdLevel1()
        console.log(funcName + " => groupIdLevel1_0p=" + groupIdLevel1_0p)
        return groupIdLevel1_0p
      }
    }

    // public int getSimCarrierId()
    // public int android.telephony.TelephonyManager.getSimCarrierId()
    var func_TelephonyManager_getSimCarrierId = cls_TelephonyManager.getSimCarrierId
    console.log("func_TelephonyManager_getSimCarrierId=" + func_TelephonyManager_getSimCarrierId)
    if (func_TelephonyManager_getSimCarrierId) {
      func_TelephonyManager_getSimCarrierId.implementation = function () {
        var funcName = "TelephonyManager.getSimCarrierId"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retSimCarrierId = this.getSimCarrierId()
        console.log(funcName + " => retSimCarrierId=" + retSimCarrierId)
        return retSimCarrierId
      }
    }

    // public boolean isVoiceCapable()
    // public boolean android.telephony.TelephonyManager.isVoiceCapable()
    var func_TelephonyManager_isVoiceCapable = cls_TelephonyManager.isVoiceCapable
    console.log("func_TelephonyManager_isVoiceCapable=" + func_TelephonyManager_isVoiceCapable)
    if (func_TelephonyManager_isVoiceCapable) {
      func_TelephonyManager_isVoiceCapable.implementation = function () {
        var funcName = "TelephonyManager.isVoiceCapable"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retIsVoiceCapable = this.isVoiceCapable()
        console.log(funcName + " => retIsVoiceCapable=" + retIsVoiceCapable)
        return retIsVoiceCapable
      }
    }

  }

  static ConnectivityManager() {
    var clsName_ConnectivityManager = "android.net.ConnectivityManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_ConnectivityManager)

    var cls_ConnectivityManager = Java.use(clsName_ConnectivityManager)
    console.log("cls_ConnectivityManager=" + cls_ConnectivityManager)
    
    // public NetworkInfo getActiveNetworkInfo()
    // 
    var func_ConnectivityManager_getActiveNetworkInfo = cls_ConnectivityManager.getActiveNetworkInfo
    console.log("func_ConnectivityManager_getActiveNetworkInfo=" + func_ConnectivityManager_getActiveNetworkInfo)
    if (func_ConnectivityManager_getActiveNetworkInfo) {
      func_ConnectivityManager_getActiveNetworkInfo.implementation = function () {
        var funcName = "ConnectivityManager.getActiveNetworkInfo"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retNetworkInfo = this.getActiveNetworkInfo()
        console.log(funcName + " => retNetworkInfo=" + retNetworkInfo)
        return retNetworkInfo
      }
    }

    // public Network getActiveNetwork()
    // 
    var func_ConnectivityManager_getActiveNetwork = cls_ConnectivityManager.getActiveNetwork
    console.log("func_ConnectivityManager_getActiveNetwork=" + func_ConnectivityManager_getActiveNetwork)
    if (func_ConnectivityManager_getActiveNetwork) {
      func_ConnectivityManager_getActiveNetwork.implementation = function () {
        var funcName = "ConnectivityManager.getActiveNetwork"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retNetwork = this.getActiveNetwork()
        console.log(funcName + " => retNetwork=" + retNetwork)
        return retNetwork
      }
    }

    // public NetworkCapabilities getNetworkCapabilities(Network network)
    // 
    var func_ConnectivityManager_getNetworkCapabilities = cls_ConnectivityManager.getNetworkCapabilities
    console.log("func_ConnectivityManager_getNetworkCapabilities=" + func_ConnectivityManager_getNetworkCapabilities)
    if (func_ConnectivityManager_getNetworkCapabilities) {
      func_ConnectivityManager_getNetworkCapabilities.implementation = function (network) {
        var funcName = "ConnectivityManager.getNetworkCapabilities"
        var funcParaDict = {
          "network": network
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retNetworkCapabilities = this.getNetworkCapabilities(network)
        console.log(funcName + " => retNetworkCapabilities=" + retNetworkCapabilities)
        return retNetworkCapabilities
      }
    }

  }

  static NetworkInfo() {
    var clsName_NetworkInfo = "android.net.NetworkInfo"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_NetworkInfo)

    var cls_NetworkInfo = Java.use(clsName_NetworkInfo)
    console.log("cls_NetworkInfo=" + cls_NetworkInfo)

    
    // public String getTypeName()
    // public java.lang.String android.net.NetworkInfo.getTypeName()
    var func_NetworkInfo_getTypeName = cls_NetworkInfo.getTypeName
    console.log("func_NetworkInfo_getTypeName=" + func_NetworkInfo_getTypeName)
    if (func_NetworkInfo_getTypeName) {
      func_NetworkInfo_getTypeName.implementation = function () {
        var funcName = "NetworkInfo.getTypeName"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTypeName = this.getTypeName()
        console.log(funcName + " => retTypeName=" + retTypeName)
        return retTypeName
      }
    }

    // public String getSubtypeName()
    // public java.lang.String android.net.NetworkInfo.getSubtypeName()
    var func_NetworkInfo_getSubtypeName = cls_NetworkInfo.getSubtypeName
    console.log("func_NetworkInfo_getSubtypeName=" + func_NetworkInfo_getSubtypeName)
    if (func_NetworkInfo_getSubtypeName) {
      func_NetworkInfo_getSubtypeName.implementation = function () {
        var funcName = "NetworkInfo.getSubtypeName"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retSubtypeName = this.getSubtypeName()
        console.log(funcName + " => retSubtypeName=" + retSubtypeName)
        return retSubtypeName
      }
    }

    // public boolean isRoaming()
    // public boolean android.net.NetworkInfo.isRoaming()
    var func_NetworkInfo_isRoaming = cls_NetworkInfo.isRoaming
    console.log("func_NetworkInfo_isRoaming=" + func_NetworkInfo_isRoaming)
    if (func_NetworkInfo_isRoaming) {
      func_NetworkInfo_isRoaming.implementation = function () {
        var funcName = "NetworkInfo.isRoaming"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.isRoaming()
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // public String getExtraInfo()
    // public java.lang.String android.net.NetworkInfo.getExtraInfo()
    var func_NetworkInfo_getExtraInfo = cls_NetworkInfo.getExtraInfo
    console.log("func_NetworkInfo_getExtraInfo=" + func_NetworkInfo_getExtraInfo)
    if (func_NetworkInfo_getExtraInfo) {
      func_NetworkInfo_getExtraInfo.implementation = function () {
        var funcName = "NetworkInfo.getExtraInfo"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retExtraInfo = this.getExtraInfo()
        console.log(funcName + " => retExtraInfo=" + retExtraInfo)
        return retExtraInfo
      }
    }
  
  }

  static SubscriptionManager() {
    var clsName_SubscriptionManager = "android.telephony.SubscriptionManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_SubscriptionManager)

    var cls_SubscriptionManager = Java.use(clsName_SubscriptionManager)
    console.log("cls_SubscriptionManager=" + cls_SubscriptionManager)

    
    // public List<SubscriptionInfo> getActiveSubscriptionInfoList()
    // public java.util.List android.telephony.SubscriptionManager.getActiveSubscriptionInfoList()
    var func_SubscriptionManager_getActiveSubscriptionInfoList = cls_SubscriptionManager.getActiveSubscriptionInfoList.overload()
    console.log("func_SubscriptionManager_getActiveSubscriptionInfoList=" + func_SubscriptionManager_getActiveSubscriptionInfoList)
    if (func_SubscriptionManager_getActiveSubscriptionInfoList) {
      func_SubscriptionManager_getActiveSubscriptionInfoList.implementation = function () {
        var funcName = "SubscriptionManager.getActiveSubscriptionInfoList"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retActiveSubscriptionInfoList = this.getActiveSubscriptionInfoList()
        console.log(funcName + " => retActiveSubscriptionInfoList=" + retActiveSubscriptionInfoList)
        return retActiveSubscriptionInfoList
      }
    }

    // public static int getDefaultVoiceSubscriptionId()
    // public static int android.telephony.SubscriptionManager.getDefaultVoiceSubscriptionId()
    var func_SubscriptionManager_getDefaultVoiceSubscriptionId = cls_SubscriptionManager.getDefaultVoiceSubscriptionId
    console.log("func_SubscriptionManager_getDefaultVoiceSubscriptionId=" + func_SubscriptionManager_getDefaultVoiceSubscriptionId)
    if (func_SubscriptionManager_getDefaultVoiceSubscriptionId) {
      func_SubscriptionManager_getDefaultVoiceSubscriptionId.implementation = function () {
        var funcName = "SubscriptionManager.getDefaultVoiceSubscriptionId"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retDefaultVoiceSubscriptionId = this.getDefaultVoiceSubscriptionId()
        console.log(funcName + " => retDefaultVoiceSubscriptionId=" + retDefaultVoiceSubscriptionId)
        return retDefaultVoiceSubscriptionId
      }
    }

    // public static int getDefaultDataSubscriptionId()
    // public static int android.telephony.SubscriptionManager.getDefaultDataSubscriptionId()
    var func_SubscriptionManager_getDefaultDataSubscriptionId = cls_SubscriptionManager.getDefaultDataSubscriptionId
    console.log("func_SubscriptionManager_getDefaultDataSubscriptionId=" + func_SubscriptionManager_getDefaultDataSubscriptionId)
    if (func_SubscriptionManager_getDefaultDataSubscriptionId) {
      func_SubscriptionManager_getDefaultDataSubscriptionId.implementation = function () {
        var funcName = "SubscriptionManager.getDefaultDataSubscriptionId"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retDefaultDataSubscriptionId = this.getDefaultDataSubscriptionId()
        console.log(funcName + " => retDefaultDataSubscriptionId=" + retDefaultDataSubscriptionId)
        return retDefaultDataSubscriptionId
      }
    }

    // public static int getDefaultSmsSubscriptionId()
    // public static int android.telephony.SubscriptionManager.getDefaultSmsSubscriptionId()
    var func_SubscriptionManager_getDefaultSmsSubscriptionId = cls_SubscriptionManager.getDefaultSmsSubscriptionId
    console.log("func_SubscriptionManager_getDefaultSmsSubscriptionId=" + func_SubscriptionManager_getDefaultSmsSubscriptionId)
    if (func_SubscriptionManager_getDefaultSmsSubscriptionId) {
      func_SubscriptionManager_getDefaultSmsSubscriptionId.implementation = function () {
        var funcName = "SubscriptionManager.getDefaultSmsSubscriptionId"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retDefaultSmsSubscriptionId = this.getDefaultSmsSubscriptionId()
        console.log(funcName + " => retDefaultSmsSubscriptionId=" + retDefaultSmsSubscriptionId)
        return retDefaultSmsSubscriptionId
      }
    }

  }

  static SubscriptionInfo() {
    var clsName_SubscriptionInfo = "android.telephony.SubscriptionInfo"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_SubscriptionInfo)

    var cls_SubscriptionInfo = Java.use(clsName_SubscriptionInfo)
    console.log("cls_SubscriptionInfo=" + cls_SubscriptionInfo)

    
    // public int getSubscriptionId()
    // public int android.telephony.SubscriptionInfo.getSubscriptionId()
    var func_SubscriptionInfo_getSubscriptionId = cls_SubscriptionInfo.getSubscriptionId
    console.log("func_SubscriptionInfo_getSubscriptionId=" + func_SubscriptionInfo_getSubscriptionId)
    if (func_SubscriptionInfo_getSubscriptionId) {
      func_SubscriptionInfo_getSubscriptionId.implementation = function () {
        var funcName = "SubscriptionInfo.getSubscriptionId"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retSubscriptionId = this.getSubscriptionId()
        console.log(funcName + " => retSubscriptionId=" + retSubscriptionId)
        return retSubscriptionId
      }
    }
    
    // public CharSequence getCarrierName()
    // public java.lang.CharSequence android.telephony.SubscriptionInfo.getCarrierName()
    var func_SubscriptionInfo_getCarrierName = cls_SubscriptionInfo.getCarrierName
    console.log("func_SubscriptionInfo_getCarrierName=" + func_SubscriptionInfo_getCarrierName)
    if (func_SubscriptionInfo_getCarrierName) {
      func_SubscriptionInfo_getCarrierName.implementation = function () {
        var funcName = "SubscriptionInfo.getCarrierName"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retCarrierNameCharSeq = this.getCarrierName()
        console.log(funcName + " => retCarrierNameCharSeq=" + retCarrierNameCharSeq)
        return retCarrierNameCharSeq
      }
    }
    
    // public int getDataRoaming()
    // public int android.telephony.SubscriptionInfo.getDataRoaming()
    var func_SubscriptionInfo_getDataRoaming = cls_SubscriptionInfo.getDataRoaming
    console.log("func_SubscriptionInfo_getDataRoaming=" + func_SubscriptionInfo_getDataRoaming)
    if (func_SubscriptionInfo_getDataRoaming) {
      func_SubscriptionInfo_getDataRoaming.implementation = function () {
        var funcName = "SubscriptionInfo.getDataRoaming"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retDataRoaming = this.getDataRoaming()
        console.log(funcName + " => retDataRoaming=" + retDataRoaming)
        return retDataRoaming
      }
    }

  }

  static Boolean(callback_isShowLog=null) {
    var clsName_Boolean = "java.lang.Boolean"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Boolean)

    var cls_Boolean = Java.use(clsName_Boolean)
    console.log("cls_Boolean=" + cls_Boolean)

    
    // boolean booleanValue()
    // 
    var func_Boolean_booleanValue = cls_Boolean.booleanValue
    console.log("func_Boolean_booleanValue=" + func_Boolean_booleanValue)
    if (func_Boolean_booleanValue) {
      func_Boolean_booleanValue.implementation = function () {
        var funcName = "Boolean.booleanValue"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
          console.log(funcCallAndStackStr)
        }

        var retBoolean = this.booleanValue()
        if (isShowLog) {
          console.log(funcName + " => retBoolean=" + retBoolean)
        }
        return retBoolean
      }
    }

  }

  static TimeZone() {
    var clsName_TimeZone = "android.icu.util.TimeZone"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_TimeZone)

    var cls_TimeZone = Java.use(clsName_TimeZone)
    console.log("cls_TimeZone=" + cls_TimeZone)

    
    // public static TimeZone getDefault()
    // 
    var func_TimeZone_getDefault = cls_TimeZone.getDefault
    console.log("func_TimeZone_getDefault=" + func_TimeZone_getDefault)
    if (func_TimeZone_getDefault) {
      func_TimeZone_getDefault.implementation = function () {
        var funcName = "TimeZone.getDefault"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retDefault = this.getDefault()
        console.log(funcName + " => retDefault=" + retDefault)
        return retDefault
      }
    }

    // public String getID()
    // 
    var func_TimeZone_getID = cls_TimeZone.getID
    console.log("func_TimeZone_getID=" + func_TimeZone_getID)
    if (func_TimeZone_getID) {
      func_TimeZone_getID.implementation = function () {
        var funcName = "TimeZone.getID"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retID = this.getID()
        console.log(funcName + " => retID=" + retID)
        return retID
      }
    }
  }

  static ZipFile() {
    var clsName_ZipFile = "java.util.zip.ZipFile"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_ZipFile)

    var cls_ZipFile = Java.use(clsName_ZipFile)
    console.log("cls_ZipFile=" + cls_ZipFile)

    
    // public ZipFile(File file)
    // 
    var func_ZipFile_ctor_1pf = cls_ZipFile.$init.overload('java.io.File')
    console.log("func_ZipFile_ctor_1pf=" + func_ZipFile_ctor_1pf)
    if (func_ZipFile_ctor_1pf) {
      func_ZipFile_ctor_1pf.implementation = function (file) {
        var funcName = "ZipFile_1pf"
        var funcParaDict = {
          "file": file,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(file)
        var newZipFile_1pf = this
        console.log(funcName + " => newZipFile_1pf=" + newZipFile_1pf)
        return
      }
    }

    // public ZipFile(String name)
    // 
    var func_ZipFile_ctor_1pn = cls_ZipFile.$init.overload('java.lang.String')
    console.log("func_ZipFile_ctor_1pn=" + func_ZipFile_ctor_1pn)
    if (func_ZipFile_ctor_1pn) {
      func_ZipFile_ctor_1pn.implementation = function (name) {
        var funcName = "ZipFile_1pn"
        var funcParaDict = {
          "name": name,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(name)
        var newZipFile_1pn = this
        console.log(funcName + " => newZipFile_1pn=" + newZipFile_1pn)
        return
      }
    }

    // public Enumeration<?extends ZipEntry> entries()
    // public java.util.Enumeration java.util.zip.ZipFile.entries()
    var func_ZipFile_entries = cls_ZipFile.entries
    console.log("func_ZipFile_entries=" + func_ZipFile_entries)
    if (func_ZipFile_entries) {
      func_ZipFile_entries.implementation = function () {
        var funcName = "ZipFile.entries"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retExtends_ZipEntry_ = this.entries()
        console.log(funcName + " => retExtends_ZipEntry_=" + retExtends_ZipEntry_)
        return retExtends_ZipEntry_
      }
    }

    // public InputStream getInputStream(ZipEntry entry)
    // public java.io.InputStream java.util.zip.ZipFile.getInputStream(java.util.zip.ZipEntry) throws java.io.IOException
    var func_ZipFile_getInputStream = cls_ZipFile.getInputStream
    console.log("func_ZipFile_getInputStream=" + func_ZipFile_getInputStream)
    if (func_ZipFile_getInputStream) {
      func_ZipFile_getInputStream.implementation = function (entry) {
        var funcName = "ZipFile.getInputStream"
        var funcParaDict = {
          "entry": entry,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInputStream = this.getInputStream(entry)
        console.log(funcName + " => retInputStream=" + retInputStream)
        return retInputStream
      }
    }
  }

  static MessageDigest() {
    var clsName_MessageDigest = "java.security.MessageDigest"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_MessageDigest)

    var cls_MessageDigest = Java.use(clsName_MessageDigest)
    console.log("cls_MessageDigest=" + cls_MessageDigest)

    
    // void update(byte[] input)
    // public void java.security.MessageDigest.update(byte[])
    var func_MessageDigest_update_1pi = cls_MessageDigest.update.overload('[B')
    console.log("func_MessageDigest_update_1pi=" + func_MessageDigest_update_1pi)
    if (func_MessageDigest_update_1pi) {
      func_MessageDigest_update_1pi.implementation = function (input) {
        var funcName = "MessageDigest.update_1pi"
        var funcParaDict = {
          "input": input,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.update(input)
      }
    }

    // void update(byte[] input, int offset, int len)
    // public void java.security.MessageDigest.update(byte[],int,int)
    var func_MessageDigest_update_3piol = cls_MessageDigest.update.overload('[B', 'int', 'int')
    console.log("func_MessageDigest_update_3piol=" + func_MessageDigest_update_3piol)
    if (func_MessageDigest_update_3piol) {
      func_MessageDigest_update_3piol.implementation = function (input, offset, len) {
        var funcName = "MessageDigest.update_3piol"
        var funcParaDict = {
          "input": input,
          "offset": offset,
          "len": len,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.update(input, offset, len)
      }
    }

    // byte[] digest()
    // 
    var func_MessageDigest_digest_0p = cls_MessageDigest.digest.overload()
    console.log("func_MessageDigest_digest_0p=" + func_MessageDigest_digest_0p)
    if (func_MessageDigest_digest_0p) {
      func_MessageDigest_digest_0p.implementation = function () {
        var funcName = "MessageDigest.digest_0p"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retByte___0p = this.digest()
        console.log(funcName + " => retByte___0p=" + retByte___0p)
        return retByte___0p
      }
    }
  }

  static Base64(callback_isShowLog=null) {
    var clsName_Base64 = "android.util.Base64"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Base64)

    var cls_Base64 = Java.use(clsName_Base64)
    console.log("cls_Base64=" + cls_Base64)

    // static String encodeToString(byte[] input, int offset, int len, int flags)
    // public static java.lang.String android.util.Base64.encodeToString(byte[],int,int,int)
    var func_Base64_encodeToString_4piolf = cls_Base64.encodeToString.overload('[B', 'int', 'int', 'int')
    console.log("func_Base64_encodeToString_4piolf=" + func_Base64_encodeToString_4piolf)
    if (func_Base64_encodeToString_4piolf) {
      func_Base64_encodeToString_4piolf.implementation = function (input, offset, len, flags) {
        var funcName = "Base64.encodeToString_4piolf"
        var funcParaDict = {
          "input": input,
          "offset": offset,
          "len": len,
          "flags": flags,
        }

        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retString_4piolf = this.encodeToString(input, offset, len, flags)
        if (isShowLog){
          console.log(funcName + " => retString_4piolf=" + retString_4piolf)
        }
        return retString_4piolf
      }
    }

    // static String encodeToString(byte[] input, int flags)
    // public static java.lang.String android.util.Base64.encodeToString(byte[],int)
    var func_Base64_encodeToString_2pif = cls_Base64.encodeToString.overload('[B', 'int')
    console.log("func_Base64_encodeToString_2pif=" + func_Base64_encodeToString_2pif)
    if (func_Base64_encodeToString_2pif) {
      func_Base64_encodeToString_2pif.implementation = function (input, flags) {
        var funcName = "Base64.encodeToString_2pif"
        var funcParaDict = {
          "input": input,
          "flags": flags,
        }

        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retString_2pif = this.encodeToString(input, flags)
        if (isShowLog){
          console.log(funcName + " => retString_2pif=" + retString_2pif)
        }
        return retString_2pif
      }
    }

  }

  static ActivityManager() {
    var clsName_ActivityManager = "android.app.ActivityManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_ActivityManager)

    var cls_ActivityManager = Java.use(clsName_ActivityManager)
    console.log("cls_ActivityManager=" + cls_ActivityManager)

    // public ConfigurationInfo getDeviceConfigurationInfo()
    // public android.content.pm.ConfigurationInfo android.app.ActivityManager.getDeviceConfigurationInfo()
    var func_ActivityManager_getDeviceConfigurationInfo = cls_ActivityManager.getDeviceConfigurationInfo
    console.log("func_ActivityManager_getDeviceConfigurationInfo=" + func_ActivityManager_getDeviceConfigurationInfo)
    if (func_ActivityManager_getDeviceConfigurationInfo) {
      func_ActivityManager_getDeviceConfigurationInfo.implementation = function () {
        var funcName = "ActivityManager.getDeviceConfigurationInfo"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retDeviceConfigurationInfo = this.getDeviceConfigurationInfo()
        console.log(funcName + " => retDeviceConfigurationInfo=" + retDeviceConfigurationInfo)
        FridaAndroidUtil.printClass_ConfigurationInfo(retDeviceConfigurationInfo)
        return retDeviceConfigurationInfo
      }
    }

    // void getMemoryInfo(ActivityManager.MemoryInfo outInfo)
    // public void android.app.ActivityManager.getMemoryInfo(android.app.ActivityManager$MemoryInfo)
    var func_ActivityManager_getMemoryInfo = cls_ActivityManager.getMemoryInfo
    console.log("func_ActivityManager_getMemoryInfo=" + func_ActivityManager_getMemoryInfo)
    if (func_ActivityManager_getMemoryInfo) {
      func_ActivityManager_getMemoryInfo.implementation = function (outInfo) {
        var funcName = "ActivityManager.getMemoryInfo"
        var funcParaDict = {
          "outInfo": outInfo,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.getMemoryInfo(outInfo)
        FridaAndroidUtil.printClass_ActivityManagerMemoryInfo(outInfo, "After " + funcName)
        return 
      }
    }
    
    // boolean isLowRamDevice()
    // public boolean android.app.ActivityManager.isLowRamDevice()
    var func_ActivityManager_isLowRamDevice = cls_ActivityManager.isLowRamDevice
    console.log("func_ActivityManager_isLowRamDevice=" + func_ActivityManager_isLowRamDevice)
    if (func_ActivityManager_isLowRamDevice) {
      func_ActivityManager_isLowRamDevice.implementation = function () {
        var funcName = "ActivityManager.isLowRamDevice"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var isLowRamDev = this.isLowRamDevice()
        console.log(funcName + " => isLowRamDev=" + isLowRamDev)
        return isLowRamDev
      }
    }

  }

  static DisplayManager() {
    var clsName_DisplayManager = "android.hardware.display.DisplayManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_DisplayManager)

    var cls_DisplayManager = Java.use(clsName_DisplayManager)
    console.log("cls_DisplayManager=" + cls_DisplayManager)
    
    // public Display getDisplay(int displayId)
    // 
    var func_DisplayManager_getDisplay = cls_DisplayManager.getDisplay
    console.log("func_DisplayManager_getDisplay=" + func_DisplayManager_getDisplay)
    if (func_DisplayManager_getDisplay) {
      func_DisplayManager_getDisplay.implementation = function (displayId) {
        var funcName = "DisplayManager.getDisplay"
        var funcParaDict = {
          "displayId": displayId,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retDisplay = this.getDisplay(displayId)
        console.log(funcName + " => retDisplay=" + retDisplay)
        return retDisplay
      }
    }

    // public Point getStableDisplaySize()
    // 
    var func_DisplayManager_getStableDisplaySize = cls_DisplayManager.getStableDisplaySize
    console.log("func_DisplayManager_getStableDisplaySize=" + func_DisplayManager_getStableDisplaySize)
    if (func_DisplayManager_getStableDisplaySize) {
      func_DisplayManager_getStableDisplaySize.implementation = function () {
        var funcName = "DisplayManager.getStableDisplaySize"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retStableDisplaySize = this.getStableDisplaySize()
        console.log(funcName + " => retStableDisplaySize=" + retStableDisplaySize)
        return retStableDisplaySize
      }
    }
  }

  static Display() {
    var clsName_Display = "android.view.Display"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Display)

    var cls_Display = Java.use(clsName_Display)
    console.log("cls_Display=" + cls_Display)

    
    // void getRealMetrics(DisplayMetrics outMetrics)
    // 
    var func_Display_getRealMetrics = cls_Display.getRealMetrics
    console.log("func_Display_getRealMetrics=" + func_Display_getRealMetrics)
    if (func_Display_getRealMetrics) {
      func_Display_getRealMetrics.implementation = function (outMetrics) {
        var funcName = "Display.getRealMetrics"
        var funcParaDict = {
          "outMetrics": outMetrics,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.getRealMetrics(outMetrics)
        FridaAndroidUtil.printClass_DisplayMetrics(outMetrics, `After ${funcName}`)
        return
      }
    }
  }

  static DisplayMetrics() {
    var clsName_DisplayMetrics = "android.util.DisplayMetrics"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_DisplayMetrics)

    var cls_DisplayMetrics = Java.use(clsName_DisplayMetrics)
    console.log("cls_DisplayMetrics=" + cls_DisplayMetrics)

    // public DisplayMetrics()
    // 
    var func_DisplayMetrics_ctor = cls_DisplayMetrics.$init
    console.log("func_DisplayMetrics_ctor=" + func_DisplayMetrics_ctor)
    if (func_DisplayMetrics_ctor) {
      func_DisplayMetrics_ctor.implementation = function () {
        var funcName = "DisplayMetrics"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init()
        var newDisplayMetrics = this
        console.log(funcName + " => newDisplayMetrics=" + newDisplayMetrics)
        FridaAndroidUtil.printClass_DisplayMetrics(newDisplayMetrics, "After DisplayMetrics()")
        return
      }
    }
  }

  static Resources() {
    var clsName_Resources = "android.content.res.Resources"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Resources)

    var cls_Resources = Java.use(clsName_Resources)
    console.log("cls_Resources=" + cls_Resources)

    // public Configuration getConfiguration()
    // public android.content.res.Configuration android.content.res.Resources.getConfiguration()
    var func_Resources_getConfiguration = cls_Resources.getConfiguration
    console.log("func_Resources_getConfiguration=" + func_Resources_getConfiguration)
    if (func_Resources_getConfiguration) {
      func_Resources_getConfiguration.implementation = function () {
        var funcName = "Resources.getConfiguration"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retConfiguration = this.getConfiguration()
        console.log(funcName + " => retConfiguration=" + retConfiguration)
        FridaAndroidUtil.printClass_Configuration(retConfiguration, `After ${funcName}`)
        return retConfiguration
      }
    }
  }

  static AssetManager() {
    var clsName_AssetManager = "android.content.res.AssetManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_AssetManager)

    var cls_AssetManager = Java.use(clsName_AssetManager)
    console.log("cls_AssetManager=" + cls_AssetManager)

    // public String[] getLocales()
    // 
    var func_AssetManager_getLocales = cls_AssetManager.getLocales
    console.log("func_AssetManager_getLocales=" + func_AssetManager_getLocales)
    if (func_AssetManager_getLocales) {
      func_AssetManager_getLocales.implementation = function () {
        var funcName = "AssetManager.getLocales"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retLocales = this.getLocales()
        console.log(funcName + " => retLocales=" + retLocales)
        return retLocales
      }
    }
  }

  static EGLDisplay() {
    var clsName_EGLDisplay = "android.opengl.EGLDisplay"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_EGLDisplay)

    var cls_EGLDisplay = Java.use(clsName_EGLDisplay)
    console.log("cls_EGLDisplay=" + cls_EGLDisplay)
  }

  static EGL_EGLDisplay() {
    var clsName_EGL_EGLDisplay = "javax.microedition.khronos.egl.EGLDisplay"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_EGL_EGLDisplay)

    var cls_EGL_EGLDisplay = Java.use(clsName_EGL_EGLDisplay)
    console.log("cls_EGL_EGLDisplay=" + cls_EGL_EGLDisplay)
  }

  // static EGL_EGL10() {
  //   var clsName_EGL_EGL10 = "javax.microedition.khronos.egl.EGL10"
  //   // FridaAndroidUtil.printClassAllMethodsFields(clsName_EGL_EGL10)

  //   var cls_EGL_EGL10 = Java.use(clsName_EGL_EGL10)
  //   console.log("cls_EGL_EGL10=" + cls_EGL_EGL10)
  // }

  static EGL10() {
    var clsName_EGL10 = "javax.microedition.khronos.egl.EGL10"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_EGL10)

    var cls_EGL10 = Java.use(clsName_EGL10)
    console.log("cls_EGL10=" + cls_EGL10)

    // abstract EGLDisplay eglGetDisplay(Object native_display)
    // public abstract javax.microedition.khronos.egl.EGLDisplay javax.microedition.khronos.egl.EGL10.eglGetDisplay(java.lang.Object)
    var func_EGL10_eglGetDisplay = cls_EGL10.eglGetDisplay
    console.log("func_EGL10_eglGetDisplay=" + func_EGL10_eglGetDisplay)
    if (func_EGL10_eglGetDisplay) {
      func_EGL10_eglGetDisplay.implementation = function (native_display) {
        var funcName = "EGL10.eglGetDisplay"
        var funcParaDict = {
          "native_display": native_display,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retEGLDisplay = this.eglGetDisplay(native_display)
        console.log(funcName + " => retEGLDisplay=" + retEGLDisplay)
        return retEGLDisplay
      }
    }

    // abstract boolean eglGetConfigs(EGLDisplay display, EGLConfig[] configs, int config_size, int[] num_config)
    // public abstract boolean javax.microedition.khronos.egl.EGL10.eglGetConfigs(javax.microedition.khronos.egl.EGLDisplay,javax.microedition.khronos.egl.EGLConfig[],int,int[])
    var func_EGL10_eglGetConfigs = cls_EGL10.eglGetConfigs
    console.log("func_EGL10_eglGetConfigs=" + func_EGL10_eglGetConfigs)
    if (func_EGL10_eglGetConfigs) {
      func_EGL10_eglGetConfigs.implementation = function (display, configs, config_size, num_config) {
        var funcName = "EGL10.eglGetConfigs"
        var funcParaDict = {
          "display": display,
          "configs": configs,
          "config_size": config_size,
          "num_config": num_config,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.eglGetConfigs(display, configs, config_size, num_config)
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // abstract boolean eglGetConfigAttrib(EGLDisplay display, EGLConfig config, int attribute, int[] value)
    // public abstract boolean javax.microedition.khronos.egl.EGL10.eglGetConfigAttrib(javax.microedition.khronos.egl.EGLDisplay,javax.microedition.khronos.egl.EGLConfig,int,int[])
    var func_EGL10_eglGetConfigAttrib = cls_EGL10.eglGetConfigAttrib
    console.log("func_EGL10_eglGetConfigAttrib=" + func_EGL10_eglGetConfigAttrib)
    if (func_EGL10_eglGetConfigAttrib) {
      func_EGL10_eglGetConfigAttrib.implementation = function (display, config, attribute, value) {
        var funcName = "EGL10.eglGetConfigAttrib"
        var funcParaDict = {
          "display": display,
          "config": config,
          "attribute": attribute,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.eglGetConfigAttrib(display, config, attribute, value)
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // abstract boolean eglTerminate(EGLDisplay display)
    // public abstract boolean javax.microedition.khronos.egl.EGL10.eglTerminate(javax.microedition.khronos.egl.EGLDisplay)
    var func_EGL10_eglTerminate = cls_EGL10.eglTerminate
    console.log("func_EGL10_eglTerminate=" + func_EGL10_eglTerminate)
    if (func_EGL10_eglTerminate) {
      func_EGL10_eglTerminate.implementation = function (display) {
        var funcName = "EGL10.eglTerminate"
        var funcParaDict = {
          "display": display,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.eglTerminate(display)
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }
  }

  static EGLContext() {
    var clsName_EGLContext = "javax.microedition.khronos.egl.EGLContext"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_EGLContext)

    var cls_EGLContext = Java.use(clsName_EGLContext)
    console.log("cls_EGLContext=" + cls_EGLContext)

    
    // public EGLContext()
    // 
    var func_EGLContext_ctor = cls_EGLContext.$init
    console.log("func_EGLContext_ctor=" + func_EGLContext_ctor)
    if (func_EGLContext_ctor) {
      func_EGLContext_ctor.implementation = function () {
        var funcName = "EGLContext"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init()
        var newEGLContext = this
        console.log(funcName + " => newEGLContext=" + newEGLContext)
        return
      }
    }

    // static EGL getEGL()
    // public static javax.microedition.khronos.egl.EGL javax.microedition.khronos.egl.EGLContext.getEGL()
    var func_EGLContext_getEGL = cls_EGLContext.getEGL
    console.log("func_EGLContext_getEGL=" + func_EGLContext_getEGL)
    if (func_EGLContext_getEGL) {
      func_EGLContext_getEGL.implementation = function () {
        var funcName = "EGLContext.getEGL"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retEGL = this.getEGL()
        var clsName = FridaAndroidUtil.getJavaClassName(retEGL)
        console.log(funcName + " => retEGL=" + retEGL + ", clsName=" + clsName)

        return retEGL
      }
    }

    // abstract GL getGL()
    // public abstract javax.microedition.khronos.opengles.GL javax.microedition.khronos.egl.EGLContext.getGL()
    var func_EGLContext_getGL = cls_EGLContext.getGL
    console.log("func_EGLContext_getGL=" + func_EGLContext_getGL)
    if (func_EGLContext_getGL) {
      func_EGLContext_getGL.implementation = function () {
        var funcName = "EGLContext.getGL"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retGL = this.getGL()
        console.log(funcName + " => retGL=" + retGL)
        return retGL
      }
    }
  }

  static Runtime() {
    var clsName_Runtime = "java.lang.Runtime"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Runtime)

    var cls_Runtime = Java.use(clsName_Runtime)
    console.log("cls_Runtime=" + cls_Runtime)

    // public int availableProcessors()
    // public int java.lang.Runtime.availableProcessors()
    var func_Runtime_availableProcessors = cls_Runtime.availableProcessors
    console.log("func_Runtime_availableProcessors=" + func_Runtime_availableProcessors)
    if (func_Runtime_availableProcessors) {
      func_Runtime_availableProcessors.implementation = function () {
        var funcName = "Runtime.availableProcessors"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var availableProcessors = this.availableProcessors()
        console.log(funcName + " => availableProcessors=" + availableProcessors)
        return availableProcessors
      }
    }
  }

  static KeyguardManager() {
    var clsName_KeyguardManager = "android.app.KeyguardManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_KeyguardManager)

    var cls_KeyguardManager = Java.use(clsName_KeyguardManager)
    console.log("cls_KeyguardManager=" + cls_KeyguardManager)

    
    // public boolean isDeviceSecure()
    // public boolean android.app.KeyguardManager.isDeviceSecure()
    var func_KeyguardManager_isDeviceSecure = cls_KeyguardManager.isDeviceSecure.overload()
    console.log("func_KeyguardManager_isDeviceSecure=" + func_KeyguardManager_isDeviceSecure)
    if (func_KeyguardManager_isDeviceSecure) {
      func_KeyguardManager_isDeviceSecure.implementation = function () {
        var funcName = "KeyguardManager.isDeviceSecure"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.isDeviceSecure()
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }
  }

  static SystemProperties() {
    var clsName_SystemProperties = "android.os.SystemProperties"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_SystemProperties)

    var cls_SystemProperties = Java.use(clsName_SystemProperties)
    console.log("cls_SystemProperties=" + cls_SystemProperties)

    
    // public static String get(String key)
    // public static java.lang.String android.os.SystemProperties.get(java.lang.String)
    var func_SystemProperties_get_1pk = cls_SystemProperties.get.overload('java.lang.String')
    console.log("func_SystemProperties_get_1pk=" + func_SystemProperties_get_1pk)
    if (func_SystemProperties_get_1pk) {
      func_SystemProperties_get_1pk.implementation = function (key) {
        var funcName = "SystemProperties.get(key)"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retStr_1pk = this.get(key)
        console.log(funcName + " => retStr_1pk=" + retStr_1pk)
        return retStr_1pk
      }
    }

    // public static String get(String key, String def)
    // public static java.lang.String android.os.SystemProperties.get(java.lang.String,java.lang.String)
    var func_SystemProperties_get_2pkd = cls_SystemProperties.get.overload('java.lang.String', 'java.lang.String')
    console.log("func_SystemProperties_get_2pkd=" + func_SystemProperties_get_2pkd)
    if (func_SystemProperties_get_2pkd) {
      func_SystemProperties_get_2pkd.implementation = function (key, def) {
        var funcName = "SystemProperties.get(key,def)"
        var funcParaDict = {
          "key": key,
          "def": def,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retStr_2pkd = this.get(key, def)
        console.log(funcName + " => retStr_2pkd=" + retStr_2pkd)
        return retStr_2pkd
      }
    }
  }

  static UserManager() {
    var clsName_UserManager = "android.os.UserManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_UserManager)

    var cls_UserManager = Java.use(clsName_UserManager)
    console.log("cls_UserManager=" + cls_UserManager)

    const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    // const curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // 
    // public int android.os.UserManager.getUserSerialNumber(int)
    var func_getUserSerialNumber = cls_UserManager.getUserSerialNumber
    console.log("func_getUserSerialNumber=" + func_getUserSerialNumber)
    if (func_getUserSerialNumber) {
      func_getUserSerialNumber.implementation = function (user) {
        var funcName = "UserManager.getUserSerialNumber(user)"
        var funcParaDict = {
          "user": user,
        }
        curLogFunc(funcName, funcParaDict)

        var retUserSerNr = this.getUserSerialNumber(user)
        console.log(funcName + " => retUserSerNr=" + retUserSerNr)
        return retUserSerNr
      }
    }
    
    // public boolean isUserUnlocked()
    // public boolean android.os.UserManager.isUserUnlocked()
    var func_UserManager_isUserUnlocked = cls_UserManager.isUserUnlocked.overload()
    console.log("func_UserManager_isUserUnlocked=" + func_UserManager_isUserUnlocked)
    if (func_UserManager_isUserUnlocked) {
      func_UserManager_isUserUnlocked.implementation = function() {
        var funcName = "UserManager.isUserUnlocked"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)

        var retIsUserUnlocked = this.isUserUnlocked()
        console.log(funcName + " => retIsUserUnlocked=" + retIsUserUnlocked)
        return retIsUserUnlocked
      }
    }

  }

  static StringBuilder(callback_isShowLog=null) {
    var clsName_StringBuilder = "java.lang.StringBuilder"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_StringBuilder)

    var cls_StringBuilder = Java.use(clsName_StringBuilder)
    console.log("cls_StringBuilder=" + cls_StringBuilder)

    // // public String toString()
    // // public java.lang.String java.lang.StringBuilder.toString()
    // var func_StringBuilder_toString = cls_StringBuilder.toString
    // console.log("func_StringBuilder_toString=" + func_StringBuilder_toString)
    // if (func_StringBuilder_toString) {
    //   func_StringBuilder_toString.implementation = function () {
    //     var funcName = "StringBuilder.toString"
    //     var funcParaDict = {}

    //     var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

    //     var isShowLog = true
    //     if (null != callback_isShowLog) {
    //       isShowLog = callback_isShowLog(funcCallAndStackStr)
    //     }

    //     // if (isShowLog) {
    //     //   console.log(funcCallAndStackStr)
    //     // }

    //     var retString = this.toString()

    //     if (isShowLog) {
    //       console.log(funcName + " => retString=" + retString)
    //     }

    //     return retString
    //   }
    // }

    // public StringBuilder append(String str)
    // public java.lang.AbstractStringBuilder java.lang.StringBuilder.append(java.lang.String)
    var func_StringBuilder_append_1ps = cls_StringBuilder.append.overload('java.lang.String')
    console.log("func_StringBuilder_append_1ps=" + func_StringBuilder_append_1ps)
    if (func_StringBuilder_append_1ps) {
      func_StringBuilder_append_1ps.implementation = function (str) {
        var funcName = "StringBuilder.append(str)"
        var funcParaDict = {
          "str": str,
        }
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        var retStringBuilder_1ps = this.append(str)

        if (isShowLog) {
          console.log(funcName + " => retStringBuilder_1ps=" + retStringBuilder_1ps)
        }

        return retStringBuilder_1ps
      }
    }

  }

  static ArrayBlockingQueue() {
    var clsName_ArrayBlockingQueue = "java.util.concurrent.ArrayBlockingQueue"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_ArrayBlockingQueue)

    var cls_ArrayBlockingQueue = Java.use(clsName_ArrayBlockingQueue)
    console.log("cls_ArrayBlockingQueue=" + cls_ArrayBlockingQueue)

    // public ArrayBlockingQueue(int capacity)
    // 
    var func_ArrayBlockingQueue_ctor_1pc = cls_ArrayBlockingQueue.$init.overload('int')
    console.log("func_ArrayBlockingQueue_ctor_1pc=" + func_ArrayBlockingQueue_ctor_1pc)
    if (func_ArrayBlockingQueue_ctor_1pc) {
      func_ArrayBlockingQueue_ctor_1pc.implementation = function (capacity) {
        var funcName = "ArrayBlockingQueue_1pc"
        var funcParaDict = {
          "capacity": capacity,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(capacity)
        var newArrayBlockingQueue_1pc = this
        console.log(funcName + " => newArrayBlockingQueue_1pc=" + newArrayBlockingQueue_1pc)
        return
      }
    }

    // public boolean offer(E e)
    // public boolean java.util.concurrent.ArrayBlockingQueue.offer(java.lang.Object)
    var func_ArrayBlockingQueue_offer_1pe = cls_ArrayBlockingQueue.offer.overload('java.lang.Object')
    console.log("func_ArrayBlockingQueue_offer_1pe=" + func_ArrayBlockingQueue_offer_1pe)
    if (func_ArrayBlockingQueue_offer_1pe) {
      func_ArrayBlockingQueue_offer_1pe.implementation = function (e) {
        var funcName = "ArrayBlockingQueue.offer_1pe"
        var funcParaDict = {
          "e": e,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean_1pe = this.offer(e)
        console.log(funcName + " => retBoolean_1pe=" + retBoolean_1pe)
        return retBoolean_1pe
      }
    }

    // public E poll()
    // public java.lang.Object java.util.concurrent.ArrayBlockingQueue.poll()
    var func_ArrayBlockingQueue_poll_0p = cls_ArrayBlockingQueue.poll.overload()
    console.log("func_ArrayBlockingQueue_poll_0p=" + func_ArrayBlockingQueue_poll_0p)
    if (func_ArrayBlockingQueue_poll_0p) {
      func_ArrayBlockingQueue_poll_0p.implementation = function () {
        var funcName = "ArrayBlockingQueue.poll_0p"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retE_0p = this.poll()
        console.log(funcName + " => retE_0p=" + retE_0p)
        return retE_0p
      }
    }
  }

  static Parcel(callback_isShowLog=null) {
    var clsName_Parcel = "android.os.Parcel"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Parcel)

    var cls_Parcel = Java.use(clsName_Parcel)
    console.log("cls_Parcel=" + cls_Parcel)

    // static Parcel obtain()
    // public static android.os.Parcel android.os.Parcel.obtain()
    var func_Parcel_obtain = cls_Parcel.obtain.overload()
    console.log("func_Parcel_obtain=" + func_Parcel_obtain)
    if (func_Parcel_obtain) {
      func_Parcel_obtain.implementation = function () {
        var funcName = "Parcel.obtain"
        var funcParaDict = {}
        // var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        var retParcel = this.obtain()

        if (isShowLog) {
          console.log(funcName + " => retParcel=" + retParcel)
        }

        return retParcel
      }
    }

    // byte[] createByteArray()
    // public final byte[] android.os.Parcel.createByteArray()
    var func_Parcel_createByteArray = cls_Parcel.createByteArray
    console.log("func_Parcel_createByteArray=" + func_Parcel_createByteArray)
    if (func_Parcel_createByteArray) {
      func_Parcel_createByteArray.implementation = function () {
        var funcName = "Parcel.createByteArray"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        var retByte__ = this.createByteArray()

        if (isShowLog) {
          console.log(funcName + " => retByte__=" + retByte__)
        }

        return retByte__
      }
    }

    // void writeMap(Map<K, V> val)
    // public final void android.os.Parcel.writeMap(java.util.Map)
    var func_Parcel_writeMap = cls_Parcel.writeMap
    console.log("func_Parcel_writeMap=" + func_Parcel_writeMap)
    if (func_Parcel_writeMap) {
      func_Parcel_writeMap.implementation = function (val) {
        var funcName = "Parcel.writeMap"
        var funcParaDict = {
          "val": val,
        }
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        this.writeMap(val)
        return 
      }
    }

    // void writeInterfaceToken(String interfaceName)
    // public final void android.os.Parcel.writeInterfaceToken(java.lang.String)
    var func_Parcel_writeInterfaceToken = cls_Parcel.writeInterfaceToken
    console.log("func_Parcel_writeInterfaceToken=" + func_Parcel_writeInterfaceToken)
    if (func_Parcel_writeInterfaceToken) {
      func_Parcel_writeInterfaceToken.implementation = function (interfaceName) {
        var funcName = "Parcel.writeInterfaceToken"
        var funcParaDict = {
          "interfaceName": interfaceName,
        }
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        this.writeInterfaceToken(interfaceName)
        return 
      }
    }

    // void readException()
    // public final void android.os.Parcel.readException()
    var func_Parcel_readException_0p = cls_Parcel.readException.overload()
    console.log("func_Parcel_readException_0p=" + func_Parcel_readException_0p)
    if (func_Parcel_readException_0p) {
      func_Parcel_readException_0p.implementation = function () {
        var funcName = "Parcel.readException_0p"
        var funcParaDict = {}
        // var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        return this.readException()        
      }
    }

    // void writeParcelable(Parcelable p, int parcelableFlags)
    // public final void android.os.Parcel.writeParcelable(android.os.Parcelable,int)
    var func_Parcel_writeParcelable = cls_Parcel.writeParcelable
    console.log("func_Parcel_writeParcelable=" + func_Parcel_writeParcelable)
    if (func_Parcel_writeParcelable) {
      func_Parcel_writeParcelable.implementation = function (p, parcelableFlags) {
        var funcName = "Parcel.writeParcelable"
        var funcParaDict = {
          "p": p,
          "parcelableFlags": parcelableFlags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        return this.writeParcelable(p, parcelableFlags)
      }
    }

    // IBinder readStrongBinder()
    // public final android.os.IBinder android.os.Parcel.readStrongBinder()
    var func_Parcel_readStrongBinder = cls_Parcel.readStrongBinder
    console.log("func_Parcel_readStrongBinder=" + func_Parcel_readStrongBinder)
    if (func_Parcel_readStrongBinder) {
      func_Parcel_readStrongBinder.implementation = function () {
        var funcName = "Parcel.readStrongBinder"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        var retIBinder = this.readStrongBinder()

        if (isShowLog) {
          var binderInterfaceDescriptor = retIBinder.getInterfaceDescriptor()
          console.log(funcName + " => retIBinder=" + FridaAndroidUtil.valueToNameStr(retIBinder) + ", binderInterfaceDescriptor=" + binderInterfaceDescriptor)
        }

        return retIBinder
      }
    }

  }

  static BinderProxy(callback_isShowLog=null) {
    var clsName_BinderProxy = "android.os.BinderProxy"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_BinderProxy)

    var cls_BinderProxy = Java.use(clsName_BinderProxy)
    console.log("cls_BinderProxy=" + cls_BinderProxy)

    // public boolean transact(int code, Parcel data, Parcel reply, int flags) throws RemoteException
    // public boolean android.os.BinderProxy.transact(int,android.os.Parcel,android.os.Parcel,int) throws android.os.RemoteException
    var func_BinderProxy_transact = cls_BinderProxy.transact
    console.log("func_BinderProxy_transact=" + func_BinderProxy_transact)
    if (func_BinderProxy_transact) {
      func_BinderProxy_transact.implementation = function (code, data, reply, flags) {
        var funcName = "BinderProxy.transact"
        var funcParaDict = {
          "code": code,
          "data": data,
          "reply": reply,
          "flags": flags,
        }

        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }
        if (isShowLog) {
          console.log(funcCallAndStackStr)
          console.log(funcName + "data=" + FridaAndroidUtil.printClass_Parcel(data) + ", reply=" + FridaAndroidUtil.printClass_Parcel(reply))
        }

        var retBoolean = this.transact(code, data, reply, flags)

        if (isShowLog) {
          console.log(funcName + " => retBoolean=" + retBoolean)
        }

        return retBoolean
      }
    }

  }

  static FileInputStream() {
    var clsName_FileInputStream = "java.io.FileInputStream"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_FileInputStream)

    var cls_FileInputStream = Java.use(clsName_FileInputStream)
    console.log("cls_FileInputStream=" + cls_FileInputStream)

    // public FileInputStream(File file) throws FileNotFoundException
    // 
    var func_FileInputStream_ctor_1pf = cls_FileInputStream.$init.overload('java.io.File')
    console.log("func_FileInputStream_ctor_1pf=" + func_FileInputStream_ctor_1pf)
    if (func_FileInputStream_ctor_1pf) {
      func_FileInputStream_ctor_1pf.implementation = function (file) {
        var funcName = "FileInputStream_1pf"
        var funcParaDict = {
          "file": file,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(file)
        var newFileInputStream_1pf = this
        console.log(funcName + " => newFileInputStream_1pf=" + newFileInputStream_1pf)
        return
      }
    }

    // public FileInputStream(FileDescriptor fdObj) throws SecurityException
    // 
    var func_FileInputStream_ctor_1pf = cls_FileInputStream.$init.overload('java.io.FileDescriptor')
    console.log("func_FileInputStream_ctor_1pf=" + func_FileInputStream_ctor_1pf)
    if (func_FileInputStream_ctor_1pf) {
      func_FileInputStream_ctor_1pf.implementation = function (fdObj) {
        var funcName = "FileInputStream_1pf"
        var funcParaDict = {
          "fdObj": fdObj,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(fdObj)
        var newFileInputStream_1pf = this
        console.log(funcName + " => newFileInputStream_1pf=" + newFileInputStream_1pf)
        return
      }
    }

    // public FileInputStream(String name) throws FileNotFoundException
    // 
    var func_FileInputStream_ctor_1pn = cls_FileInputStream.$init.overload('java.lang.String')
    console.log("func_FileInputStream_ctor_1pn=" + func_FileInputStream_ctor_1pn)
    if (func_FileInputStream_ctor_1pn) {
      func_FileInputStream_ctor_1pn.implementation = function (name) {
        var funcName = "FileInputStream_1pn"
        var funcParaDict = {
          "name": name,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(name)
        var newFileInputStream_1pn = this
        console.log(funcName + " => newFileInputStream_1pn=" + newFileInputStream_1pn)
        return
      }
    }

    // public FileChannel getChannel()
    // 
    var func_FileInputStream_getChannel = cls_FileInputStream.getChannel
    console.log("func_FileInputStream_getChannel=" + func_FileInputStream_getChannel)
    if (func_FileInputStream_getChannel) {
      func_FileInputStream_getChannel.implementation = function () {
        var funcName = "FileInputStream.getChannel"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retChannel = this.getChannel()
        console.log(funcName + " => retChannel=" + retChannel)
        return retChannel
      }
    }
  }

  static LinkedBlockingQueue(callback_isShowLog=null) {
    var clsName_LinkedBlockingQueue = "java.util.concurrent.LinkedBlockingQueue"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_LinkedBlockingQueue)

    var cls_LinkedBlockingQueue = Java.use(clsName_LinkedBlockingQueue)
    console.log("cls_LinkedBlockingQueue=" + cls_LinkedBlockingQueue)

    
    // public LinkedBlockingQueue()
    // 
    var func_LinkedBlockingQueue_ctor_0p = cls_LinkedBlockingQueue.$init.overload()
    console.log("func_LinkedBlockingQueue_ctor_0p=" + func_LinkedBlockingQueue_ctor_0p)
    if (func_LinkedBlockingQueue_ctor_0p) {
      func_LinkedBlockingQueue_ctor_0p.implementation = function () {
        var funcName = "LinkedBlockingQueue_0p"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        this.$init()
        var newLinkedBlockingQueue_0p = this
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => newLinkedBlockingQueue_0p=${newLinkedBlockingQueue_0p}`, false)
        return
      }
    }

    // boolean offer(E e)
    // public boolean java.util.concurrent.LinkedBlockingQueue.offer(java.lang.Object)
    var func_LinkedBlockingQueue_offer_1pe = cls_LinkedBlockingQueue.offer.overload("java.lang.Object")
    console.log("func_LinkedBlockingQueue_offer_1pe=" + func_LinkedBlockingQueue_offer_1pe)
    if (func_LinkedBlockingQueue_offer_1pe) {
      func_LinkedBlockingQueue_offer_1pe.implementation = function (e) {
        var funcName = "LinkedBlockingQueue.offer_1pe"
        var funcParaDict = {
          "e": e,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean_1pe = this.offer(e)
        console.log(funcName + " => retBoolean_1pe=" + retBoolean_1pe)
        return retBoolean_1pe
      }
    }

    // boolean offer(E e, long timeout, TimeUnit unit)
    // public boolean java.util.concurrent.LinkedBlockingQueue.offer(java.lang.Object,long,java.util.concurrent.TimeUnit) throws java.lang.InterruptedException
    var func_LinkedBlockingQueue_offer_3petu = cls_LinkedBlockingQueue.offer.overload("java.lang.Object", "long", "java.util.concurrent.TimeUnit")
    console.log("func_LinkedBlockingQueue_offer_3petu=" + func_LinkedBlockingQueue_offer_3petu)
    if (func_LinkedBlockingQueue_offer_3petu) {
      func_LinkedBlockingQueue_offer_3petu.implementation = function (e, timeout, unit) {
        var funcName = "LinkedBlockingQueue.offer_3petu"
        var funcParaDict = {
          "e": e,
          "timeout": timeout,
          "unit": unit,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean_3petu = this.offer(e, timeout, unit)
        console.log(funcName + " => retBoolean_3petu=" + retBoolean_3petu)
        return retBoolean_3petu
      }
    }

    // E poll()
    // public java.lang.Object java.util.concurrent.LinkedBlockingQueue.poll()
    var func_LinkedBlockingQueue_poll_0p = cls_LinkedBlockingQueue.poll.overload()
    console.log("func_LinkedBlockingQueue_poll_0p=" + func_LinkedBlockingQueue_poll_0p)
    if (func_LinkedBlockingQueue_poll_0p) {
      func_LinkedBlockingQueue_poll_0p.implementation = function () {
        var funcName = "LinkedBlockingQueue.poll_0p"
        var funcParaDict = {}
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        // var isShowLog = true
        var isShowLog = false
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }
        if (isShowLog) {
          // console.log(funcCallAndStackStr)
        }

        var retE_0p = this.poll()

        if (isShowLog) {
          if (retE_0p) {
            console.log(funcCallAndStackStr)

            console.log(funcName + " => retE_0p=" + FridaAndroidUtil.valueToNameStr(retE_0p))
          }
        }

        return retE_0p
      }
    }

    // E poll(long timeout, TimeUnit unit)
    // public java.lang.Object java.util.concurrent.LinkedBlockingQueue.poll(long,java.util.concurrent.TimeUnit) throws java.lang.InterruptedException
    var func_LinkedBlockingQueue_poll_2ptu = cls_LinkedBlockingQueue.poll.overload("long", "java.util.concurrent.TimeUnit")
    console.log("func_LinkedBlockingQueue_poll_2ptu=" + func_LinkedBlockingQueue_poll_2ptu)
    if (func_LinkedBlockingQueue_poll_2ptu) {
      func_LinkedBlockingQueue_poll_2ptu.implementation = function (timeout, unit) {
        var funcName = "LinkedBlockingQueue.poll_2ptu"
        var funcParaDict = {
          "timeout": timeout,
          "unit": unit,
        }
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        // var isShowLog = true
        var isShowLog = false
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }
        if (isShowLog) {
          // console.log(funcCallAndStackStr)
        }

        var retE_2ptu = this.poll(timeout, unit)

        if (isShowLog) {
          if (retE_2ptu) {
            console.log(funcCallAndStackStr)

            console.log(funcName + " => retE_2ptu=" + FridaAndroidUtil.valueToNameStr(retE_2ptu))
          }
        }

        return retE_2ptu
      }
    }

    // void put(E e)
    // public void java.util.concurrent.LinkedBlockingQueue.put(java.lang.Object) throws java.lang.InterruptedException
    var func_LinkedBlockingQueue_put = cls_LinkedBlockingQueue.put
    console.log("func_LinkedBlockingQueue_put=" + func_LinkedBlockingQueue_put)
    if (func_LinkedBlockingQueue_put) {
      func_LinkedBlockingQueue_put.implementation = function (e) {
        var funcName = "LinkedBlockingQueue.put"
        var funcParaDict = {
          "e": e,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.put(e)
      }
    }

  }

}

// https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaHookAndroidNative.js
// Updated: 20250626
// Frida hook Android native and JNI related functions
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

  static android_dlopen_ext(libraryName=null, callback_afterLibLoaded=null){
    console.log("android_dlopen_ext: libraryName=" + libraryName + ", callback_afterLibLoaded=" + callback_afterLibLoaded)
    // var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext")
    var funcPtr_android_dlopen_ext = Module.getExportByName(null, "android_dlopen_ext")
    console.log("funcPtr_android_dlopen_ext=" + funcPtr_android_dlopen_ext)
    if (null == funcPtr_android_dlopen_ext) {
      console.log("[-] Not found android_dlopen_ext")
      return
    }

    Interceptor.attach(funcPtr_android_dlopen_ext, {
      onEnter: function (args) {
        // android_dlopen_ext(const char *_Nullable __filename, int __flags, const android_dlextinfo *_Nullable __info)	

        // console.log("args=" + args)
        var filenamePtr = args[0]
        var libFullPath = FridaUtil.ptrToCStr(filenamePtr)
        // console.log("libFullPath=" + libFullPath)
        var flags = args[1]
        var info = args[2]
        if (libraryName) {
          // if(libraryName === libFullPath){
          if(libFullPath.includes(libraryName)){
            console.log("+++ Loaded lib " + libraryName + ", flags=" + flags + ", info=" + info)
            this.isLibLoaded = true

            this._libFullPath = libFullPath
          }
        } else {
          console.log("android_dlopen_ext: [+] libFullPath=" + libFullPath + ", flags=" + flags + ", info=" + info)
        }
      },
  
      onLeave: function () {
        if (libraryName) {
          if (this.isLibLoaded) {
            this.isLibLoaded = false
    
            // if(null != callback_afterLibLoaded) {
            if(callback_afterLibLoaded) {
              // callback_afterLibLoaded(libraryName)
              callback_afterLibLoaded(this._libFullPath)
            }
          }
        }
      }
    })
  
  }

  static waitForLibLoading(libraryName, callback_afterLibLoaded=null){
    console.log("waitForLibLoading: libraryName=" + libraryName + ", callback_afterLibLoaded=" + callback_afterLibLoaded)
    FridaHookAndroidNative.android_dlopen_ext(libraryName, callback_afterLibLoaded)

    // // var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext")
    // var android_dlopen_ext = Module.getExportByName(null, "android_dlopen_ext")
    // console.log("android_dlopen_ext=" + android_dlopen_ext)
    // if (null == android_dlopen_ext) {
    //   return
    // }
  
    // Interceptor.attach(android_dlopen_ext, {
    //   onEnter: function (args) {
    //     // android_dlopen_ext(const char *_Nullable __filename, int __flags, const android_dlextinfo *_Nullable __info)	

    //     // console.log("args=" + args)
    //     var filenamePtr = args[0]
    //     var libFullPath = FridaUtil.ptrToCStr(filenamePtr)
    //     // console.log("libFullPath=" + libFullPath)
    //     var flags = args[1]
    //     var info = args[2]
    //     // console.log("android_dlopen_ext: [+] libFullPath=" + libFullPath + ", flags=" + flags + ", info=" + info)
    //     // if(libraryName === libFullPath){
    //     if(libFullPath.includes(libraryName)){
    //       console.log("+++ Loaded lib " + libraryName + ", flags=" + flags + ", info=" + info)
    //       this.isLibLoaded = true

    //       this._libFullPath = libFullPath
    //     }
    //   },
  
    //   onLeave: function () {
    //     if (this.isLibLoaded) {
    //       this.isLibLoaded = false
  
    //       if(null != callback_afterLibLoaded) {
    //         // callback_afterLibLoaded(libraryName)
    //         callback_afterLibLoaded(this._libFullPath)
    //       }
    //     }
    //   }
    // })
  }

  static hookAfterLibLoaded(libName, callback_afterLibLoaded=null){
    console.log("libName=" + libName)
    FridaHookAndroidNative.waitForLibLoading(libName, callback_afterLibLoaded)
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
    var foundSymbolList = FridaHookAndroidNative.findSymbolFromLib("libart.so", jniFuncName, func_isFound)
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
    var jniSymbolList = FridaHookAndroidNative.findFunction_libart_so(jniFuncName, FridaHookAndroidNative.isFoundSymbol)
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
    var jniSymbolList = FridaHookAndroidNative.findJniFunc(jniFuncName)
    FridaHookAndroidNative.doHookJniFunc_multipleMatch(jniSymbolList, hookFunc_onEnter, hookFunc_onLeave)
  }

  static hookNative_NewStringUTF(){
    FridaHookAndroidNative.hookJniFunc(
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
    FridaHookAndroidNative.hookJniFunc(
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

    FridaHookAndroidNative.hookJniFunc(
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

        FridaHookAndroidNative.printJNINativeMethodDetail(methodsPtr, methodNum)
      }
    )
  }

}

// https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaHookNative.js
// Updated: 20251023
// Frida hook common native functions
class FridaHookNative {
  // static dladdr = null
  // static free = null

  constructor() {
    console.log("FridaHookNative constructor")
  }

  static {
    console.log("FridaHookNative static")
    // FridaHookNative.dladdr = FridaHookNative.genNativeFunc_dladdr()
    // console.log("FridaHookNative.dladdr=" + FridaHookNative.dladdr)

    // FridaHookNative.free = FridaHookNative.genNativeFunc_free()
    // console.log("FridaHookNative.free=" + FridaHookNative.free)
  }

  static hookNative_commonFunc(funcName_native, funcParaList, libFullPath=null, funcName_log=null, isPrintStack=true){
    console.log("hookNative_commonFunc: funcName_native=" + funcName_native + ", funcParaList=" + funcParaList + ", libFullPath=" + libFullPath + ", funcName_log=" + funcName_log)

    var foundNativeFunc = Module.findExportByName(libFullPath, funcName_native)
    console.log("foundNativeFunc=" + foundNativeFunc)
    if (null != foundNativeFunc) {
      Interceptor.attach(foundNativeFunc, {
        onEnter: function (args) {
          // var curFuncName = ""
          // if (funcName_log){
          //   curFuncName = funcName_log
          // } else {
          //   curFuncName = funcName_native
          // }
          // console.log("curFuncName=" + curFuncName)
          // JsUtil.logStr(curFuncName)

          if (isPrintStack){
            // console.log("funcName_log=" + funcName_log)
            FridaUtil.printFunctionCallStack_addr(this.context, funcName_log)
          } else {
            console.log(funcName_log + " called")
          }

          // var logStr = funcName_log + ": [+] libFullPath=" + libFullPath
          // var logStr = `${funcName_log}: [+] libFullPath=${libFullPath}`
          var logStr = `${funcName_log}: [+]`

          // for(var curParaName in funcParaList){
          for (let paraIdx = 0; paraIdx < funcParaList.length; paraIdx++) {
            var curParaValue = args[paraIdx]
            // console.log("curParaValue=" + curParaValue)

            let curParaCfg = funcParaList[paraIdx]
            // console.log("curParaCfg=" + curParaCfg)
            var curParaCfgType = typeof curParaCfg
            // console.log("curParaCfgType=" + curParaCfgType)

            var curParaLog = ""

            var curParaName = null
            if (curParaCfgType === "string"){
              curParaName = curParaCfg

              curParaLog = `${curParaName}=${curParaValue}`
            } else {
              curParaLog = `${curParaName}=${curParaValue}`

              // is 'object' == dict = json
              var curParaDict = curParaCfg
              curParaName = curParaDict["paraName"]
              // console.log("curParaName=" + curParaName)
              var curParaType = curParaDict["paraType"]
              // console.log("curParaType=" + curParaType)

              // if (curParaType == "string"){
              if (curParaType == FridaUtil.StringType.CString){
                // curParaValue = FridaUtil.ptrToUtf8Str(curParaValue)
                var curParaValuePtr = curParaValue
                curParaValue = FridaUtil.ptrToCStr(curParaValuePtr)
                // console.log("curParaValue=" + curParaValue)

                curParaLog = `${curParaName}=${curParaValuePtr}=${curParaValue}`
              // } else if (curParaType == "stdstring"){
              } else if (curParaType == FridaUtil.StringType.StdString){
                var curParaValuePtr = curParaValue
                curParaValue = FridaUtil.ptrToStdStr(curParaValuePtr)
                // console.log("curParaValue=" + curParaValue)

                curParaLog = `${curParaName}=${curParaValuePtr}=${curParaValue}`
              }
            }

            // console.log("[" + paraIdx + "] " + curParaName + "=" + curParaValue)

            if (paraIdx == 0) {
              logStr = `${logStr} ${curParaLog}`
            } else {
              logStr = `${logStr}, ${curParaLog}`
            }
          }
      
          console.log(logStr)
        },
        onLeave: function (retval) {
          console.log("\t " + funcName_log + " retval=" + retval)
        }
      })
    } else {
      console.error("Failed to find function " + funcName_log + " in lib " + libFullPath)
    }
  
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

  static hookNative_access(){
    // int access(const char *pathname, int mode);
    Interceptor.attach(Module.findExportByName(null, "access"), {
      onEnter: function (args) {
        var pathname = FridaUtil.ptrToCStr(args[0])
        var mode = args[1]
        console.log("access: [+] pathname=" + pathname + ", mode=" + mode)
        this._pathname = pathname
        this._mode = mode
        FridaUtil.printFunctionCallStack_addr(this.context, "hookNative_access")
      },
      onLeave: function (retVal) {
        console.log("access: [+] pathname=" + this._pathname + ", mode=" + this._mode + " -> retVal=" + retVal)
      }
    })
  }

  static hookNative_faccessat(){
    // int faccessat(int dirfd, const char *pathname, int mode, int flags);
    Interceptor.attach(Module.findExportByName(null, "faccessat"), {
      onEnter: function (args) {
        var dirfd = args[0]
        var pathname = FridaUtil.ptrToCStr(args[1])
        var mode = args[2]
        var flags = args[3]
        console.log("faccessat: [+] dirfd=" + dirfd + ", pathname=" + pathname + ", mode=" + mode + ", flags=" + flags)
        this._dirfd = dirfd
        this._pathname = pathname
        this._mode = mode
        this._flags = flags
        FridaUtil.printFunctionCallStack_addr(this.context, "hookNative_faccessat")
      },
      onLeave: function (retVal) {
        console.log("faccessat: [+] dirfd=" + this._dirfd + ", pathname=" + this._pathname + ", mode=" + this._mode + ", flags=" + this._flags + " -> retVal=" + retVal)
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

        FridaUtil.printFunctionCallStack_addr(this.context, "hookNative_fopen")
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

        FridaUtil.printFunctionCallStack_addr(this.context, "hookNative_pthread_create")
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

  static func_isShowLog_URL(curStr){
    return FridaAndroidUtil.func_isShowLog_common(curStr, ["sync", "intermediateIntegrity"])
  }

  static func_isShowLog_File(curStr){
    return FridaAndroidUtil.func_isShowLog_common(curStr, ["express_integrity"])
  }

  static func_isShowLog_String(curStr){
    var isShowLog = false

    // console.log(`func_isShowLog_String: curStr: type=${typeof curStr}, val=${curStr}`)
    var strLen = curStr.length
    // console.log(`func_isShowLog_String: strLen=${strLen}, curStr=${curStr}`)
    const LargeStrLen = 20 * 1024 // for DroidGuardResultStr is about 20KB, 30KB, even 40KB large
    if (strLen > LargeStrLen) {
      isShowLog = true
    }
    return isShowLog
  }

  static func_isShowLog_StringBuilder(curStr){
    return Hook_SomeApp.func_isShowLog_String(curStr)
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
        console.log(funcName + " => ret_api=" + ret_api)
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
        console.log(funcName + " => ret_api2=" + ret_api2)
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
        console.log(funcName + " => ret_strStr=" + ret_strStr)
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
        console.log(funcName + " => ret_strBArr=" + ret_strBArr)
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

        this.a(eventsBean, bVar)
        return
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
        
        this.a(z3)
        return
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

  FridaHookAndroidJava.URL(Hook_SomeApp.func_isShowLog_URL)
  FridaHookAndroidJava.File(Hook_SomeApp.func_isShowLog_File)
  FridaHookAndroidJava.String(Hook_SomeApp.func_isShowLog_String)
  FridaHookAndroidJava.StringBuilder(Hook_SomeApp.func_isShowLog_StringBuilder)

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
