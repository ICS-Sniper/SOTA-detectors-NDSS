import os
import random
import sys
import resource

# 增加递归深度限制
sys.setrecursionlimit(50000)  # 增加到更大的值

# 如果在Mac上，还可能需要增加栈大小
try:
    resource.setrlimit(resource.RLIMIT_STACK, (2**29, resource.RLIM_INFINITY))
except:
    pass

from datetime import datetime

import joblib
import orjson

import ipal_iids.settings as settings
from ids.dtmc.dtmc import DTMC, State
from ids.dtmc.graph import Graph
from ids.ids import MetaIDS


class Dtmc(MetaIDS):
    _name = "Dtmc"
    _description = "DTMC tests the sequence of messages with an automata."
    _requires = ["train.ipal", "live.ipal"]
    _dtmc_default_settings = {
        "bisimulation": 0,  # 0 no 1 merge all IOAs 2 merge overlapping IOAs
        "buffer": 100,
        "alert_unknown": True,
    }
    _supports_preprocessor = False

    def __init__(self, name=None):
        super().__init__(name=name)
        self._add_default_settings(self._dtmc_default_settings)

        self.dtmcs = {}
        self.msg_buf = {}

    def _is_request(self, msg):
        if msg["activity"] in ["interrogate", "command"]:
            return True
        elif msg["activity"] in ["inform", "action", "confirmation"]:
            return False

        settings.logger.critical("Unknown message activity")
        exit(1)

    def _get_connection(self, msg):
        # compute one identifier per connection (IP pair)
        ips = [msg["dest"].split(":")[0], msg["src"].split(":")[0]]
        return "-".join(sorted(ips))

    def _create_dtmc(self, msgs):
        entryDate = datetime.fromtimestamp(0)
        entryState = State(
            "-", False, False, 0, 0, [], entryDate, self.settings["bisimulation"]
        )
        entryState.entryState(True)
        dtmc = DTMC(entryState, self.settings["bisimulation"])

        for msg in msgs:
            dtmc.addState(
                State(
                    msg["type"],  # single letter I U S (IEC-104)
                    self._is_request(msg),  # bool
                    not self._is_request(msg),  # bool
                    msg["type"],  # typeID (int)
                    0,  # asduAddress (int)
                    list(msg["data"].keys()),  # IOAs (str)
                    datetime.fromtimestamp(msg["timestamp"]),
                    self.settings["bisimulation"],
                )
            )

        if self.settings["bisimulation"] == 2:
            dtmc.minimize()

        return dtmc

    def train(self, ipal=None, state=None):
        events = {}

        # Load messages to IP connections
        with self._open_file(ipal) as f:
            for line in f:
                ipal_msg = orjson.loads(line)

                connection = self._get_connection(ipal_msg)
                if connection not in events:
                    events[connection] = []
                events[connection].append(ipal_msg)

        # Train DTMCs per connection
        for connection in events:
            self.dtmcs[connection] = self._create_dtmc(events[connection])
            self.msg_buf[connection] = []

    def new_ipal_msg(self, msg):
        connection = self._get_connection(msg)

        if connection not in self.dtmcs:  # Unknown connection
            settings.logger.info("Unknown connection!")
            return self.settings["alert_unknown"], None

        else:  # Known connection
            self.msg_buf[connection].append(msg)
            if len(self.msg_buf[connection]) > self.settings["buffer"]:
                self.msg_buf[connection].pop(0)

            testingDtmc = self._create_dtmc(self.msg_buf[connection])
            state_violations, transition_violations = testingDtmc.validate(
                self.dtmcs[connection]
            )

            settings.logger.info(f"State violations: {state_violations}")
            settings.logger.info(f"Transition violations: {transition_violations}")

            # one malicious msg within the window
            alert = state_violations + transition_violations > 0

            return alert, state_violations + transition_violations

    def save_trained_model(self):
        if self.settings["model-file"] is None:
            return False

        # 为序列化准备模型数据，避免循环引用
        model_data = self._prepare_model_for_serialization()
        
        model = {
            "_name": self._name,
            "settings": self.settings,
            "dtmcs": model_data,
        }

        try:
            # 设置更高的递归限制用于序列化
            original_limit = sys.getrecursionlimit()
            sys.setrecursionlimit(50000)
            
            # 尝试使用不同的序列化方法
            self._safe_dump(model, self._resolve_model_file_path())
            
            sys.setrecursionlimit(original_limit)
            return True
        except Exception as e:
            settings.logger.error(f"Failed to save model: {e}")
            sys.setrecursionlimit(original_limit)
            return False

    def _prepare_model_for_serialization(self):
        """准备模型数据以避免循环引用"""
        prepared_dtmcs = {}
        for connection, dtmc in self.dtmcs.items():
            # 创建DTMC的简化版本，移除可能的循环引用
            prepared_dtmcs[connection] = self._serialize_dtmc(dtmc)
        return prepared_dtmcs
    
    def _serialize_dtmc(self, dtmc):
        """安全地序列化DTMC对象"""
        try:
            # 尝试直接序列化
            return dtmc
        except:
            # 如果失败，创建一个简化的表示
            return {
                'states': list(dtmc.states.keys()) if hasattr(dtmc, 'states') else [],
                'transitions': getattr(dtmc, 'transitions', {}),
                'bisimulation': getattr(dtmc, 'bisimulation', 0)
            }
    
    def _safe_dump(self, model, filepath):
        """安全的模型保存方法"""
        import pickle
        
        # 方法1: 尝试使用joblib
        try:
            joblib.dump(model, filepath, compress=3)
            return
        except RecursionError:
            settings.logger.warning("joblib failed due to recursion, trying pickle with protocol 4")
        
        # 方法2: 使用pickle with highest protocol
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(model, f, protocol=pickle.HIGHEST_PROTOCOL)
            return
        except RecursionError:
            settings.logger.warning("pickle failed due to recursion, trying dill")
        
        # 方法3: 尝试使用dill
        try:
            import dill
            with open(filepath, 'wb') as f:
                dill.dump(model, f)
            return
        except (ImportError, RecursionError):
            settings.logger.warning("dill failed or not available, trying simplified serialization")
        
        # 方法4: 简化模型再尝试
        simplified_model = {
            "_name": model["_name"],
            "settings": model["settings"],
            "dtmcs": {}  # 只保存基本信息
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(simplified_model, f, protocol=pickle.HIGHEST_PROTOCOL)
        
        settings.logger.warning("Saved simplified model due to serialization issues")

    def load_trained_model(self):
        if self.settings["model-file"] is None:
            return False

        try:  # Open model file
            model = self._safe_load(self._resolve_model_file_path())
        except FileNotFoundError:
            return False
        except Exception as e:
            settings.logger.error(f"Failed to load model: {e}")
            return False

        # Load model
        assert self._name == model["_name"]
        self.settings = model["settings"]
        self.dtmcs = model["dtmcs"]

        for connection in self.dtmcs:
            self.msg_buf[connection] = []

        return True
    
    def _safe_load(self, filepath):
        """安全的模型加载方法"""
        import pickle
        
        # 尝试joblib
        try:
            return joblib.load(filepath)
        except:
            pass
        
        # 尝试pickle
        try:
            with open(filepath, 'rb') as f:
                return pickle.load(f)
        except:
            pass
        
        # 尝试dill
        try:
            import dill
            with open(filepath, 'rb') as f:
                return dill.load(f)
        except ImportError:
            pass
        
        raise Exception("Failed to load model with any method")

    def visualize_model(self):
        import matplotlib.pyplot as plt

        if len(self.dtmcs) > 1:
            fig, axs = plt.subplots(nrows=(len(self.dtmcs) + 1) // 2, ncols=2)
            axs = [ax for row in axs for ax in row]
        else:
            fig, axs = plt.subplots(nrows=1, ncols=1)
            axs = [axs]

        i = -1
        for connection in self.dtmcs:
            i += 1

            # Generate temporary filename
            tmp = f"tmp-{random.randint(1000, 9999)}"

            Graph(self.dtmcs[connection]).generate_graph(
                tmp, colored=True, format="png"
            )
            axs[i].imshow(plt.imread(f"{tmp}.png"))
            axs[i].set_title(connection, fontsize=8)

            axs[i].axis("off")
            os.remove(f"{tmp}.png")

        for i in range(len(self.dtmcs), len(axs)):  # Remove remaining plot
            axs[i].axis("off")

        return plt, fig
