const { evaluateContextualDecision } = require('./decisionEngine');

/**
 * Risk & Security Context Evaluation Wrapper
 * Delegates to decisionEngine.js for explainable decision matrix evaluation.
 */

async function evaluateRisk(userId, req, operationType, dataClassification = 'INTERNAL') {
  return await evaluateContextualDecision(userId, req, operationType, dataClassification);
}

module.exports = {
  evaluateRisk,
};
