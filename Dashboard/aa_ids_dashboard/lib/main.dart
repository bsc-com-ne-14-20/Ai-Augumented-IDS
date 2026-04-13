import 'package:aa_ids_dashboard/ui/theming/app_theme.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '/state/auth_provider.dart';
import '/state/theme_provider.dart';
import '/ui/screens/login_screen.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => AuthProvider()),
        ChangeNotifierProvider(create: (_) => ThemeProvider()),
      ],
      child: Consumer<ThemeProvider>(
        builder: (context, themeProvider, _) {
          return MaterialApp(
            title: 'AA-IDS Dashboard',
            theme: themeProvider.isDarkTheme
                ? AppTheme.darkTheme
                : AppTheme.lightTheme,
            home: const LoginScreen(),
            debugShowCheckedModeBanner: false,
          );
        },
      ),
    );
  }
}
