import 'package:flutter/material.dart';

class IdsLogo extends StatelessWidget {
  final double size;

  const IdsLogo({
    super.key,
    this.size = 80,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: const BoxDecoration(
        color: Color(0xFF2196F3), 
        shape: BoxShape.circle,
      ),
      child: Center(
        child: Icon(
          Icons.shield,           // Shield icon 
          size: size * 0.55,
          color: Colors.white,
        ),
      ),
    );
  }
}