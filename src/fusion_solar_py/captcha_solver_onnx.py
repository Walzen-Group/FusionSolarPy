import cv2
import numpy as np
import onnxruntime as rt

from fusion_solar_py.interfaces import GenericSolver

from .ctc_decoder import decode

alphabet = ['2', '3', '4', '5', '6', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'l', 'r', 't', 'y']
blank_idx = 20

class Solver(GenericSolver):

    def _init_model(self):
        self.session = rt.InferenceSession("D:\\Code\\Repos\\walzen-group\\FusionSolarPy\\src\\fusion_solar_py\\captcha_huawei.onnx", providers=self.device)


    def solve_captcha(self, img):
        if type(img) != np.ndarray:
            img = np.frombuffer(img, np.uint8)
            img = cv2.imdecode(img, cv2.IMREAD_GRAYSCALE)
        img = self.preprocess_image(img)
        img = np.expand_dims(img, axis=0)
        out = self.session.run(None, {"image": img.astype(np.float32), "label": None})
        return self.decode_batch_predictions(out[0])

    def decode_batch_predictions(self, pred):
        # Use greedy search. For complex tasks, you can use beam search
        results = decode(pred[0], beam_size=10, blank=blank_idx)
        # Iterate over the results and get back the text
        output_text = list(map(lambda n: alphabet[n-1], results[0]))
        return ''.join(output_text)

    def preprocess_image(self, img):
        if len(img.shape) == 3:
            img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        img = img / 255.0
        # swap axis
        img = np.swapaxes(img, 0, 1)
        img = np.expand_dims(img, axis=2)
        return img
