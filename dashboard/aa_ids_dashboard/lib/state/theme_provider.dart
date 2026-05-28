import 'package:flutter/material.dart';

class ThemeProvider extends ChangeNotifier {
  bool _isDarkTheme = true;

  bool get isDarkTheme => _isDarkTheme;
  bool get isLightTheme => !_isDarkTheme;

  void toggleTheme() {
    _isDarkTheme = !_isDarkTheme;
    notifyListeners();
  }

  void setDarkTheme() {
    _isDarkTheme = true;
    notifyListeners();
  }

  void setLightTheme() {
    _isDarkTheme = false;
    notifyListeners();
  }
}
