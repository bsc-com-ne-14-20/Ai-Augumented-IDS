class AuthApi {
  /// Hardcoded authentication with username=Admin and password=Dennis
  Future<bool> login(String username, String password) async {
    // Hardcoded credentials for now
    const String validUsername = 'Admin';
    const String validPassword = 'Dennis';

    if (username == validUsername && password == validPassword) {
      return true;
    } else {
      throw Exception('Invalid username or password');
    }
  }
}