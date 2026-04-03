import 'package:flutter/material.dart';
import '/api/auth_api.dart';

class AuthProvider extends ChangeNotifier {
  // Instance of the API class
  final AuthApi _authApi = AuthApi();

  bool _isLoading = false;
  String? _errorMessage;
  bool _isAuthenticated = false;

  // Getters for the UI to consume
  bool get isLoading => _isLoading;
  String? get errorMessage => _errorMessage;
  bool get isAuthenticated => _isAuthenticated;

  /// Handles the login logic and notifies listeners of state changes
  Future<void> login(String email, String password) async {
    _isLoading = true;
    _errorMessage = null;
    notifyListeners();

    try {
      _isAuthenticated = await _authApi.login(email, password);
    } catch (e) {
      _isAuthenticated = false;
      _errorMessage = e.toString().replaceAll('Exception: ', '');
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  void logout() {
    _isAuthenticated = false;
    notifyListeners();
  }
}