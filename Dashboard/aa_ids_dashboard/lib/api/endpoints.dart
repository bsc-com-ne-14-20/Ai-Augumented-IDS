import 'package:aa_ids_dashboard/constants.dart';

/// A centralized class to manage all API endpoints.
class ApiEndpoints {
  // Authentication Section
  static const String _authBase = '${AppConstants.baseUrl}/auth/';

  static const String login = '${_authBase}login';
  static const String register = '${_authBase}register';
  static const String forgotPassword = '${_authBase}forgot-password';
}