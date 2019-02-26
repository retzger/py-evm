import enum
import logging
import os
from typing import (
    NewType,
)

import numpy

import pytest

from eth_keys import keys

from eth_utils import (
    to_bytes,
    to_tuple,
    ValidationError,
)

from eth_hash.auto import keccak

from eth_typing.enums import (
    ForkName
)

from rlp.sedes import (
    CountableList,
)

from wasm.datatypes import (
    Configuration,
    ExportInstance,
    FunctionType,
    MemoryType,
    ModuleInstance,
    Store,
    ValType,
)


from eth.db import (
    get_db_backend,
)
from eth.db.chain import ChainDB

from eth.rlp.headers import (
    BlockHeader,
)
from eth.tools._utils.hashing import (
    hash_log_entries,
)
from eth.tools.fixtures import (
    filter_fixtures,
    generate_fixture_tests,
    load_fixture,
    normalize_statetest_fixture,
    should_run_slow_tests,
)
from eth.utils.db import (
    apply_state_dict,
)


from eth.vm.forks.petersburg import PetersburgVM
from eth.vm.forks.petersburg.blocks import PetersburgBlock
from eth.vm.forks.petersburg.state import PetersburgState
from eth.vm.forks.petersburg.computation import PetersburgComputation
from eth.vm.forks.petersburg.transactions import (
    PetersburgTransaction,
    PetersburgUnsignedTransaction,
)


logger = logging.getLogger('ewasm.debug')


u128 = NewType('u128', int)
u256 = NewType('u256', int)
i32ptr = NewType('i32ptr', numpy.uint32)
address = NewType('address', int)


#
# Ewasm Stuff
#
class EEIValType(enum.Enum):
    bytes = bytes
    address = address
    u128 = u128
    u256 = u256
    i32 = numpy.uint32
    i64 = numpy.uint64
    i32ptr = i32ptr


def _printXX(config):
    value = config.pop_operand()
    config.push_operand(value)
    logger.info('%s', value)


def _printMem(config):
    pass


def create_debug_module():
    pass


def useGas(config: Configuration) -> None:
    pass


def getAddress(config: Configuration) -> None:
    pass


params_i64_results_none = FunctionType(
    (ValType.i64,),
    (),
)
params_i32_results_none = FunctionType(
    (ValType.i32,),
    (),
)

EEI_META = (
    ('useGas', useGas, params_i64_results_none),
    ('getAddress', getAddress, params_i32_results_none),
)


def create_EEI_module(store: Store) -> ModuleInstance:
    """
    - useGas
    - getAddress
    - getExternalBalance
    - getBlockHash
    - call
    - callDataCopy
    - getCallDataSize
    - callCode
    - callDelegate
    - callStatic
    - storageStore
    - storageLoad
    - getCaller
    - getCallValue
    - codeCopy
    - getCodeSize
    - getBlockCoinbase
    - create
    - getBlockDifficulty
    - externalCodeCopy
    - getExternalCodeSize
    - getGasLeft
    - getBlockGassLimit
    - getTxGasPrice
    - log
    - getBlockNumber
    - getTxOrigin
    - finish
    - revert
    - getReturnDataSize
    - returnDataCopy
    - selfDestruct
    - getBlockTimestamp
    """
    function_addresses = tuple(
        store.allocate_host_function(function_type, eei_fn)
        for _, eei_fn, function_type
        in EEI_META
    )
    types = tuple(
        function_type
        for _, eei_fn, function_type
        in EEI_META
    )

    memory_address = store.allocate_memory(MemoryType(numpy.uint32(1), None))

    exports = tuple(
        ExportInstance(function_name, function_address)
        for ((function_name, _, _), function_address)
        in zip(EEI_META, function_addresses)
    ) + (
        ExportInstance('memory', memory_address),
    )

    eei = ModuleInstance(
        types=types,
        func_addrs=function_addresses,
        table_addrs=(),
        memory_addrs=(memory_address,),
        global_addrs=(),
        exports=exports,
    )
    return eei


#
# Ethereum Stuff
#
class EWASMTransaction(PetersburgTransaction):
    pass


class EWASMUnsignedTransaction(PetersburgUnsignedTransaction):
    pass


class EWASMBlock(PetersburgBlock):
    transaction_class = EWASMTransaction
    fields = [
        ('header', BlockHeader),
        ('transactions', CountableList(transaction_class)),
        ('uncles', CountableList(BlockHeader))
    ]


class EWASMComputation(PetersburgComputation):
    pass


class EWASMState(PetersburgState):
    computation_class = EWASMComputation


class EWASMVM(PetersburgVM):
    block_class = EWASMBlock
    _state_class = EWASMState


#
#  ACTUAL TEST FIXTURE EXECUTION
#
ROOT_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))


BASE_FIXTURE_PATH = os.path.join(ROOT_PROJECT_DIR, 'fixtures', 'GeneralStateTests')


logger = logging.getLogger('eth.tests.fixtures.ewasm')


@to_tuple
def expand_fixtures_forks(all_fixtures):
    """
    The statetest fixtures have different definitions for each fork and must be
    expanded one step further to have one fixture for each defined fork within
    the fixture.
    """

    for fixture_path, fixture_key in all_fixtures:
        fixture = load_fixture(fixture_path, fixture_key)
        for fixture_fork, post_states in sorted(fixture['post'].items()):
            for post_state_index in range(len(post_states)):
                yield fixture_path, fixture_key, fixture_fork, post_state_index


# These are the slowest 50 tests from the full statetest run.  This list should
# be regenerated occasionally using `--durations 50`.
SLOWEST_TESTS = {
}


# These are tests that are thought to be incorrect or buggy upstream,
# at the commit currently checked out in submodule `fixtures`.
# Ideally, this list should be empty.
# WHEN ADDING ENTRIES, ALWAYS PROVIDE AN EXPLANATION!
INCORRECT_UPSTREAM_TESTS = {
}


def mark_statetest_fixtures(fixture_path, fixture_key, fixture_fork, fixture_index):
    fixture_id = (fixture_path, fixture_key, fixture_fork, fixture_index)

    if fixture_id in SLOWEST_TESTS:
        if should_run_slow_tests():
            return
        else:
            return pytest.mark.skip("Skipping slow test")
    elif fixture.path.startswith('stEWASMTests/'):
        return
    else:
        return pytest.mark.skip("Non-EWASM test")


def generate_ignore_fn_for_fork(metafunc):
    """
    The statetest fixtures have different definitions for each fork and we must ensure to only run
    test against against the intended fork (e.g run Constantinople state tests against
    Constantinople VM).
    We can not rely on `pytest -k` matching for that as that matches against an identification
    string that includes the path and name of the test which in some cases also contains fork
    fork names. A test file may be named "ConstantinopleSomething.json" but still contains
    individual definitions per fork.
    """
    passed_fork = metafunc.config.getoption('fork')
    if passed_fork:
        passed_fork = passed_fork.lower()

        def ignore_fn(fixture_path, fixture_key, fixture_fork, post_state_index):
            return fixture_fork.lower() != passed_fork

        return ignore_fn


def pytest_generate_tests(metafunc):
    generate_fixture_tests(
        metafunc=metafunc,
        base_fixture_path=BASE_FIXTURE_PATH,
        preprocess_fn=expand_fixtures_forks,
        filter_fn=filter_fixtures(
            ignore_fn=generate_ignore_fn_for_fork(metafunc),
            fixtures_base_dir=BASE_FIXTURE_PATH,
            mark_fn=mark_statetest_fixtures,
        ),
    )


@pytest.fixture
def fixture(fixture_data):
    fixture_path, fixture_key, fixture_fork, post_state_index = fixture_data
    fixture = load_fixture(
        fixture_path,
        fixture_key,
        normalize_statetest_fixture(fork=fixture_fork, post_state_index=post_state_index),
    )
    return fixture


#
# Test Chain Setup
#
def get_block_hash_for_testing(self, block_number):
    if block_number >= self.block_number:
        return b''
    elif block_number < 0:
        return b''
    elif block_number < self.block_number - 256:
        return b''
    else:
        return keccak(to_bytes(text="{0}".format(block_number)))


def get_prev_hashes_testing(self, last_block_hash, db):
    prev_hashes = []
    return prev_hashes


EWASMVMForTesting = EWASMVM.configure(
    __name__='EWASMVMForTesting',
    get_prev_hashes=get_prev_hashes_testing,
)


@pytest.fixture
def fixture_vm_class(fixture_data):
    _, _, fork_name, _ = fixture_data
    if fork_name == ForkName.Byzantium:
        return EWASMVMForTesting
    elif fork_name == ForkName.Constantinople:
        pytest.skip("Constantinople VM has not been implemented")
    elif fork_name == ForkName.Metropolis:
        pytest.skip("Metropolis VM has not been implemented")
    else:
        raise ValueError("Unknown Fork Name: {0}".format(fork_name))


def test_state_fixtures(fixture, fixture_vm_class):
    header = BlockHeader(
        coinbase=fixture['env']['currentCoinbase'],
        difficulty=fixture['env']['currentDifficulty'],
        block_number=fixture['env']['currentNumber'],
        gas_limit=fixture['env']['currentGasLimit'],
        timestamp=fixture['env']['currentTimestamp'],
        parent_hash=fixture['env']['previousHash'],
    )

    chaindb = ChainDB(get_db_backend())
    vm = fixture_vm_class(header=header, chaindb=chaindb)

    state = vm.state
    apply_state_dict(state.account_db, fixture['pre'])
    state.account_db.persist()

    # Update state_root manually
    vm.block = vm.block.copy(header=vm.block.header.copy(state_root=state.state_root))
    if 'secretKey' in fixture['transaction']:
        unsigned_transaction = vm.create_unsigned_transaction(
            nonce=fixture['transaction']['nonce'],
            gas_price=fixture['transaction']['gasPrice'],
            gas=fixture['transaction']['gasLimit'],
            to=fixture['transaction']['to'],
            value=fixture['transaction']['value'],
            data=fixture['transaction']['data'],
        )
        private_key = keys.PrivateKey(fixture['transaction']['secretKey'])
        transaction = unsigned_transaction.as_signed_transaction(private_key=private_key)
    elif 'vrs' in fixture['transaction']:
        v, r, s = (
            fixture['transaction']['v'],
            fixture['transaction']['r'],
            fixture['transaction']['s'],
        )
        transaction = vm.create_transaction(
            nonce=fixture['transaction']['nonce'],
            gas_price=fixture['transaction']['gasPrice'],
            gas=fixture['transaction']['gasLimit'],
            to=fixture['transaction']['to'],
            value=fixture['transaction']['value'],
            data=fixture['transaction']['data'],
            v=v,
            r=r,
            s=s,
        )
    else:
        raise Exception("Invariant: No transaction specified")

    try:
        header, receipt, computation = vm.apply_transaction(vm.block.header, transaction)
    except ValidationError as err:
        logger.warning("Got transaction error", exc_info=True)
        transaction_error = err
    else:
        transaction_error = False

        transactions = vm.block.transactions + (transaction, )
        receipts = vm.block.get_receipts(chaindb) + (receipt, )
        vm.block = vm.set_block_transactions(vm.block, header, transactions, receipts)
    finally:
        # This is necessary due to the manner in which the state tests are
        # generated. State tests are generated from the BlockChainTest tests
        # in which these transactions are included in the larger context of a
        # block and thus, the mechanisms which would touch/create/clear the
        # coinbase account based on the mining reward are present during test
        # generation, but not part of the execution, thus we must artificially
        # create the account in VMs prior to the state clearing rules,
        # as well as conditionally cleaning up the coinbase account when left
        # empty in VMs after the state clearing rules came into effect.
        # Related change in geth:
        # https://github.com/ethereum/go-ethereum/commit/32f28a9360d26a661d55915915f12fd3c70f012b#diff-f53696be8527ac422b8d4de7c8e945c1R149  # noqa: E501

        if state.account_db.account_is_empty(vm.block.header.coinbase):
            state.account_db.delete_account(vm.block.header.coinbase)
            state.account_db.persist()
            vm.block = vm.block.copy(header=vm.block.header.copy(state_root=state.state_root))

        block = vm.block

    if not transaction_error:
        log_entries = computation.get_log_entries()
        actual_logs_hash = hash_log_entries(log_entries)
        if 'logs' in fixture['post']:
            expected_logs_hash = fixture['post']['logs']
            assert expected_logs_hash == actual_logs_hash
        elif log_entries:
            raise AssertionError("Got log {0} entries. hash:{1}".format(
                len(log_entries),
                actual_logs_hash,
            ))

        if 'out' in fixture:
            expected_output = fixture['out']
            if isinstance(expected_output, int):
                assert len(computation.output) == expected_output
            else:
                assert computation.output == expected_output

    assert block.header.state_root == fixture['post']['hash']
