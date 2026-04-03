class AuthApi {
  /// Mocks an API call for user authentication.
  Future<bool> login(String email, String password) async {
    // Simulating network latency
    await Future.delayed(const Duration(seconds: 2));

    // Mock validation logic
    if (email == 'admin@example.com' && password == 'password123') {
      return true;
    } else {
      // Throwing an exception to simulate an error response from an API
      throw Exception('Invalid email or password. Use admin@example.com / password123');
    }
  }
}