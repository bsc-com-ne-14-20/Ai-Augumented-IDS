import 'package:aa_ids_dashboard/constants.dart';

/// A centralized class to manage all API endpoints.
class ApiEndpoints {
  // API Version Base
  static const String _apiBase = '${AppConstants.baseUrl}/api/v1';

  // Authentication Section
  static const String _authBase = '${AppConstants.baseUrl}/auth/';
  static const String login = '${_authBase}login';
  static const String register = '${_authBase}register';
  static const String forgotPassword = '${_authBase}forgot-password';

  // Dashboard Health & Status
  static const String health = '$_apiBase/health';

  // Analysis & Detection
  static const String analyze = '$_apiBase/analyze';

  // Metrics & Dashboard Data
  static const String metrics = '$_apiBase/stats';

  // Alerts & Incidents
  static const String alerts = '$_apiBase/alerts';

  // Socket.IO
  static const String socketUrl = AppConstants.baseUrl;
}