import tempfile
import unittest
from pathlib import Path
import numpy as np
from evaluate_replay_df import encoded_trace, row_key


class EncodingTests(unittest.TestCase):
    def trace(self, text, length=5):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'trace'
            path.write_text(text)
            return encoded_trace(path, length)

    def test_zero_packet_retained_stable_tie_order_and_padding(self):
        result = self.trace('0 -1\n0.2 1\n0.1 -1\n0.1 1\n')
        np.testing.assert_array_equal(np.sign(result), [-1, -1, 1, 1, 0])
        self.assertLess(result[0], 0)

    def test_truncation_is_after_timestamp_sort(self):
        np.testing.assert_array_equal(np.sign(self.trace('0.2 1\n0.1 -1\n', 1)), [-1])

    def test_invalid_direction_and_timestamp_rejected(self):
        for text in ['0 0\n', '-1 1\n', 'nan 1\n', '0 512\n']:
            with self.assertRaises(ValueError):
                self.trace(text)

    def test_split_match_requires_same_label_and_full_content(self):
        a = np.array([1, -2], dtype=np.float32)
        self.assertNotEqual(row_key(a, 0), row_key(a, 1))
        self.assertNotEqual(row_key(a, 0), row_key(np.array([1, -3]), 0))


if __name__ == '__main__':
    unittest.main()
