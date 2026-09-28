import { DEMO_SCENARIO_STEPS } from './demoScenario';
import type { DemoStep } from './demoScenario';

export class DemoController {
  private isRunning: boolean = false;
  private currentStepIndex: number = 0;
  private timerId: ReturnType<typeof setTimeout> | number | null = null;
  private onStepCallback?: (step: DemoStep, index: number) => void;
  private onCompleteCallback?: () => void;

  public start(
    onStep: (step: DemoStep, index: number) => void,
    onComplete: () => void
  ) {
    if (this.isRunning) {
      this.stop();
    }

    this.isRunning = true;
    this.currentStepIndex = 0;
    this.onStepCallback = onStep;
    this.onCompleteCallback = onComplete;

    this.executeNextStep();
  }

  private executeNextStep() {
    if (!this.isRunning) return;

    if (this.currentStepIndex >= DEMO_SCENARIO_STEPS.length) {
      this.isRunning = false;
      if (this.onCompleteCallback) {
        this.onCompleteCallback();
      }
      return;
    }

    const step = DEMO_SCENARIO_STEPS[this.currentStepIndex];

    // Trigger step update
    if (this.onStepCallback) {
      this.onStepCallback(step, this.currentStepIndex);
    }

    this.currentStepIndex++;

    if (this.currentStepIndex < DEMO_SCENARIO_STEPS.length) {
      const nextStep = DEMO_SCENARIO_STEPS[this.currentStepIndex];
      this.timerId = setTimeout(() => {
        this.executeNextStep();
      }, nextStep.delayMs);
    }
  }

  public stop() {
    this.isRunning = false;
    if (this.timerId !== null) {
      clearTimeout(this.timerId as unknown as number);
      this.timerId = null;
    }
  }

  public getIsRunning(): boolean {
    return this.isRunning;
  }
}

export const globalDemoController = new DemoController();
