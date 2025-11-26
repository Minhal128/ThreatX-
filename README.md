# ThreatX-

![Static Analysis](https://imgur.com/JD5onYl.jpg)

ThreatX is an AI-based malware detection system that utilizes deep learning models for the identification of malware or malicious files. This repository includes both YARA rules for pattern matching and Python code for the AI models.

## Features

- **Static Analysis Using AI**: Leverages AI for analyzing files without executing them.
  ![Static Analysis Using AI](https://imgur.com/Ckdi1Px.jpg)

- **Dynamic Analysis Using AI**: Uses AI to analyze the behavior of files during execution.
  ![Dynamic Analysis Using AI](https://imgur.com/QRZg2DY.jpg)

- **Integration with YARA Rules**: Utilizes YARA for efficient pattern matching and malware signature detection.

## Language Composition

- **YARA**: 73.7%
- **Python**: 11.6%
- **JavaScript**: 8.6%
- **HTML**: 6%
- **CSS**: 0.1%

## Why YARA and Python?

Even though the main detection logic is implemented in Python, YARA rules play a crucial role in the system by providing a powerful and flexible way to define and identify malware patterns. This combination ensures both efficiency and accuracy in malware detection. YARA is widely used in the industry for its specialized capabilities, making it an essential component of the ThreatX system.

## Installation

To set up the environment and run the project, follow these steps:

1. Clone the repository:
   ```sh
   git clone https://github.com/Minhal128/ThreatX-.git
   cd ThreatX-
   ```

2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

3. Run the application:
   ```sh
   python main.py
   ```
## CLI PHASE
![CLI PHASE](https://imgur.com/YzWlbXZ.png)

## Usage

To use ThreatX for malware detection, you can follow the instructions provided in the `docs` directory. The system allows for both static and dynamic analysis of files.

## Contributing

Contributions are welcome! Please read the [CONTRIBUTING](CONTRIBUTING.md) guidelines before submitting a pull request.

## Contact

For any inquiries or support, please contact [Minhal128](https://github.com/Minhal128).
email: rminhal783@gmail.com
