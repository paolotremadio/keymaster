// Keymaster, access Keychain secrets guarded by TouchID
//
import AppKit
import Foundation
import LocalAuthentication

let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics
let maxCommandLength = 100

func setPassword(key: String, password: String) -> Bool {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecValueData as String: password
  ]

  let status = SecItemAdd(query as CFDictionary, nil)
  return status == errSecSuccess
}

func deletePassword(key: String) -> Bool {
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecMatchLimit as String: kSecMatchLimitOne
  ]
  let status = SecItemDelete(query as CFDictionary)
  return status == errSecSuccess
}

func getPassword(key: String) -> String? {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecReturnData as String: true
  ]
  var item: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &item)

  guard status == errSecSuccess,
    let passwordData = item as? Data,
    let password = String(data: passwordData, encoding: String.Encoding.utf8)
  else { return nil }

  return password
}

func parentPID(of pid: pid_t) -> pid_t? {
  var info = kinfo_proc()
  var size = MemoryLayout<kinfo_proc>.stride
  var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
  guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0, size > 0 else { return nil }
  return info.kp_eproc.e_ppid
}

func executableName(of pid: pid_t) -> String {
  var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
  guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return "pid \(pid)" }
  return (String(cString: buffer) as NSString).lastPathComponent
}

// KERN_PROCARGS2 layout: argc (Int32), executable path, NUL padding, then argc NUL-terminated arguments.
func arguments(of pid: pid_t) -> [String] {
  var argmax: Int32 = 0
  var size = MemoryLayout<Int32>.size
  var mib: [Int32] = [CTL_KERN, KERN_ARGMAX]
  guard sysctl(&mib, UInt32(mib.count), &argmax, &size, nil, 0) == 0 else { return [] }

  var buffer = [UInt8](repeating: 0, count: Int(argmax))
  size = buffer.count
  mib = [CTL_KERN, KERN_PROCARGS2, pid]
  guard sysctl(&mib, UInt32(mib.count), &buffer, &size, nil, 0) == 0,
    size > MemoryLayout<Int32>.size
  else { return [] }

  let argc = buffer.withUnsafeBytes { $0.load(as: Int32.self) }
  var index = MemoryLayout<Int32>.size
  while index < size && buffer[index] != 0 { index += 1 }
  while index < size && buffer[index] == 0 { index += 1 }

  var args: [String] = []
  while args.count < argc && index < size {
    let start = index
    while index < size && buffer[index] != 0 { index += 1 }
    args.append(String(decoding: buffer[start..<index], as: UTF8.self))
    index += 1
  }
  return args
}

// The executable is named from its real path, not argv[0], which the caller can set to anything.
func commandLine(of pid: pid_t) -> String {
  let args = arguments(of: pid).dropFirst().map { ($0 as NSString).abbreviatingWithTildeInPath }
  let command = ([executableName(of: pid)] + args).joined(separator: " ")
  guard command.count > maxCommandLength else { return command }
  // Trim the middle so both the program and the script name / trailing arguments stay visible.
  let keep = maxCommandLength - 1
  return command.prefix(keep * 2 / 5) + "…" + command.suffix(keep - keep * 2 / 5)
}

// Same approach as Secretive: walk up from the caller to the first ancestor that is a regular app
// (Terminal, iTerm2, ...). Electron helpers are registered as apps too, hence the activation policy check.
// With no regular app in the chain (ssh, cron, menu bar apps), stop at the topmost process below launchd.
func originPID(from pid: pid_t) -> pid_t {
  var current = pid
  while NSRunningApplication(processIdentifier: current)?.activationPolicy != .regular,
    let parent = parentPID(of: current), parent > 1 {
    current = parent
  }
  return current
}

func authReason(_ action: String, key: String) -> String {
  let requester = getppid()
  let origin = originPID(from: requester)
  var reason = "\(action) “\(key)” for “\(commandLine(of: requester))”"
  if origin != requester {
    let originName = NSRunningApplication(processIdentifier: origin)?.localizedName ?? executableName(of: origin)
    reason += " in \(originName)"
  }
  return reason
}

func usage() {
  print("keymaster [get|set|delete] [key] [secret]")
}

func main() {
  let inputArgs: [String] = Array(CommandLine.arguments.dropFirst())
  if (inputArgs.count < 2 || inputArgs.count > 3) {
    usage()
    exit(EXIT_FAILURE) 
  }
  let action = inputArgs[0]
  let key = inputArgs[1]
  var secret = ""
  if (action == "set" && inputArgs.count == 3) {
    secret = inputArgs[2]
  }

  let context = LAContext()
  context.touchIDAuthenticationAllowableReuseDuration = 0
  context.localizedCancelTitle = "Deny"

  var error: NSError?
  guard context.canEvaluatePolicy(policy, error: &error) else {
    print("This Mac doesn't support deviceOwnerAuthenticationWithBiometrics")
    exit(EXIT_FAILURE)
  }

  if (action == "set") {
    context.evaluatePolicy(policy, localizedReason: authReason("save secret", key: key)) { success, error in
      guard setPassword(key: key, password: secret) else {
        print("Error setting password")
        exit(EXIT_FAILURE)
      }
      print("Key \(key) has been sucessfully set in the keychain")
      exit(EXIT_SUCCESS)
    }
    dispatchMain()
  }

  if (action == "get") {
    context.evaluatePolicy(policy, localizedReason: authReason("read secret", key: key)) { success, error in
      if success && error == nil {
        guard let password = getPassword(key: key) else {
          print("Error getting password")
          exit(EXIT_FAILURE)
        }
        print(password)
        exit(EXIT_SUCCESS)
      } else {
        let errorDescription = error?.localizedDescription ?? "Unknown error"
        print("Error \(errorDescription)")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }

  if (action == "delete") {
    context.evaluatePolicy(policy, localizedReason: authReason("delete secret", key: key)) { success, error in
      if success && error == nil {
        guard deletePassword(key: key) else {
          print("Error deleting password")
          exit(EXIT_FAILURE)
        }
        print("Key \(key) has been sucessfully deleted from the keychain")
        exit(EXIT_SUCCESS)
      } else {
        let errorDescription = error?.localizedDescription ?? "Unknown error"
        print("Error \(errorDescription)")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }
}

main()
